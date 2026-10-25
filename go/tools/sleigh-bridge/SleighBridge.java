// Temporary SLEIGH bridge for the Go ra port (native Go port tracked in #19).
//
// Decodes instructions through Ghidra 12.1.4's own SLEIGH engine and reports
// Ghidra's facts over the JSON-lines contract of go/internal/ra/sleigh:
//
//   request  (one line, stdin):  {"language":ID,"batch":[{"addr":"0x..","bytes":"hex","context":"0x.."}]}
//   response (one line per batch entry, in order, stdout):
//     {"addr","len","mnemonic","text","flow","has_fallthrough","targets","indirect","context"}
//     or {"error":"message"}
//
// The bridge never re-derives flows from p-code: "flow" is Ghidra's FlowType
// name. The computed forms are normalized to the base name plus indirect=true
// (COMPUTED_JUMP -> UNCONDITIONAL_JUMP, CONDITIONAL_COMPUTED_CALL ->
// CONDITIONAL_CALL, ...). FlowTypes outside the contract (CALL_TERMINATOR,
// JUMP_TERMINATOR, CALLOTHER_OVERRIDE_*, INDIRECTION, ...) are reported as an
// error for that entry, never mapped by guesswork.
//
// "bridge --language-info ID [COMPILER_SPEC_ID]" prints the language record (one
// JSON line) the Go side parses with ParseLanguage, then exits. The calling
// convention comes from the compiler spec (the language's default one when
// none is given: for x86-64 that is Visual Studio, so pass "gcc" for ELF).
//
// Requires GHIDRA_INSTALL_DIR; refuses any Ghidra but application.version=12.1.4.
// Protocol errors that make the batch size unknown (a malformed request line)
// are answered with one {"error":...} line and the bridge exits with status 2.

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.Strictness;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class SleighBridge {
	static final String GHIDRA_VERSION = "12.1.4";

	/** An error for one entry (or, before the batch is known, for the whole request). */
	static final class BridgeError extends Exception {
		BridgeError(String message) {
			super(message);
		}
	}

	static final class Entry {
		long addr;
		byte[] bytes;
		long context;
	}

	static final class Request {
		String language;
		List<Entry> batch;
	}

	/** One loaded language with the in-memory program instructions are decoded in. */
	static final class Lang {
		final Language language;
		final ProgramDB program;
		final Register contextReg;

		Lang(Language language) throws Exception {
			this.language = language;
			CompilerSpec cspec = language.getDefaultCompilerSpec();
			this.program = new ProgramDB("sleigh-bridge", language, cspec, SleighBridge.class);
			this.contextReg = language.getContextBaseRegister();
		}
	}

	static PrintStream out;
	static final Map<String, Lang> languages = new HashMap<>();

	public static void main(String[] args) throws Exception {
		// Anything the Ghidra libraries print must not corrupt the response stream.
		out = new PrintStream(new FileOutputStream(FileDescriptor.out), false, StandardCharsets.UTF_8);
		System.setOut(System.err);

		File install = checkInstall();
		Application.initializeApplication(new GhidraApplicationLayout(install),
			new HeadlessGhidraApplicationConfiguration());
		if (!GHIDRA_VERSION.equals(Application.getApplicationVersion())) {
			die("running Ghidra reports version " + Application.getApplicationVersion() + ", need " +
				GHIDRA_VERSION);
		}

		if ((args.length == 2 || args.length == 3) && args[0].equals("--language-info")) {
			try {
				out.println(languageInfo(language(args[1]), args.length == 3 ? args[2] : null));
			}
			catch (BridgeError e) {
				die(e.getMessage());
			}
			return;
		}
		if (args.length != 0) {
			die("usage: SleighBridge [--language-info LANGUAGE_ID [COMPILER_SPEC_ID]]");
		}

		BufferedReader in = new BufferedReader(
			new InputStreamReader(new FileInputStream(FileDescriptor.in), StandardCharsets.UTF_8));
		String line;
		while ((line = in.readLine()) != null) {
			if (line.isBlank()) {
				continue;
			}
			Request req;
			try {
				req = parseRequest(line);
			}
			catch (BridgeError e) {
				out.println("{\"error\":" + quote("bad request: " + e.getMessage()) + "}");
				out.flush();
				System.exit(2);
				return;
			}
			serve(req);
			out.flush();
		}
	}

	static void die(String message) {
		System.err.println("sleigh-bridge: " + message);
		System.exit(1);
	}

	/**
	 * GHIDRA_INSTALL_DIR must be a Ghidra 12.1.4 install: the version is read from
	 * Ghidra/application.properties before anything of Ghidra is loaded.
	 */
	static File checkInstall() {
		String dir = System.getenv("GHIDRA_INSTALL_DIR");
		if (dir == null || dir.isEmpty()) {
			die("GHIDRA_INSTALL_DIR is not set; point it at a Ghidra " + GHIDRA_VERSION + " install");
		}
		File props = new File(dir, "Ghidra/application.properties");
		Properties p = new Properties();
		try (FileInputStream f = new FileInputStream(props)) {
			p.load(f);
		}
		catch (Exception e) {
			die("cannot read " + props + ": " + e.getMessage());
		}
		String version = p.getProperty("application.version");
		if (!GHIDRA_VERSION.equals(version)) {
			die("GHIDRA_INSTALL_DIR " + dir + " is Ghidra " + version + "; this bridge only works with " +
				GHIDRA_VERSION);
		}
		return new File(dir);
	}

	static Lang language(String id) throws BridgeError {
		Lang l = languages.get(id);
		if (l != null) {
			return l;
		}
		try {
			Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
			l = new Lang(lang);
		}
		catch (Exception e) {
			throw new BridgeError("cannot load language " + id + ": " + e.getMessage());
		}
		languages.put(id, l);
		return l;
	}

	// ------------------------------------------------------------------ language record

	static String hex(long v) {
		return "\"0x" + Long.toHexString(v) + "\"";
	}

	static String varnode(Register r) {
		Address a = r.getAddress();
		return "{\"space\":" + quote(a.getAddressSpace().getName()) + ",\"offset\":" +
			Long.toUnsignedString(a.getOffset()) + ",\"size\":" + r.getMinimumByteSize() + "}";
	}

	static String languageInfo(Lang l, String compilerId) throws BridgeError {
		Language lang = l.language;
		StringBuilder sb = new StringBuilder();
		sb.append("{\"id\":").append(quote(lang.getLanguageID().getIdAsString()));
		sb.append(",\"big_endian\":").append(lang.isBigEndian());
		sb.append(",\"address_size\":").append(lang.getLanguageDescription().getSize() / 8);
		long ctx = 0;
		if (l.contextReg != null) {
			if (l.contextReg.getBitLength() > 64) {
				throw new BridgeError("context register " + l.contextReg + " is wider than 64 bits");
			}
			// the value the language's context_data gives the start of its default space
			RegisterValue rv = l.program.getProgramContext().getDefaultValue(l.contextReg,
				lang.getDefaultSpace().getMinAddress());
			ctx = rv == null ? 0 : rv.getUnsignedValueIgnoreMask().longValue();
		}
		sb.append(",\"initial_context\":").append(hex(ctx));
		sb.append(",\"pc\":").append(varnode(lang.getProgramCounter()));
		CompilerSpec cspec = lang.getDefaultCompilerSpec();
		if (compilerId != null) {
			try {
				cspec = lang.getCompilerSpecByID(new CompilerSpecID(compilerId));
			}
			catch (Exception e) {
				throw new BridgeError("language " + lang.getLanguageID() + " has no compiler spec " + compilerId);
			}
		}
		Register sp = cspec.getStackPointer();
		if (sp == null) {
			throw new BridgeError("language " + lang.getLanguageID() + " has no stack pointer");
		}
		sb.append(",\"sp\":").append(varnode(sp));
		sb.append(",\"int_args\":[");
		// Integer argument registers of the default calling convention, in
		// order: ask the model where its n-th pointer-sized integer argument
		// goes until that is no longer a single register.
		PrototypeModel model = cspec.getDefaultCallingConvention();
		boolean first = true;
		if (model != null) {
			DataType dt = AbstractIntegerDataType.getUnsignedDataType(lang.getDefaultSpace().getPointerSize(),
				l.program.getDataTypeManager());
			List<Parameter> params = new ArrayList<>();
			for (int i = 0; i < 16; i++) {
				VariableStorage vs = model.getNextArgLocation(params.toArray(new Parameter[0]), dt, l.program);
				if (vs == null || !vs.isRegisterStorage() || vs.getRegister() == null) {
					break;
				}
				if (!first) {
					sb.append(',');
				}
				first = false;
				sb.append(varnode(vs.getRegister()));
				try {
					params.add(new ParameterImpl("a" + i, dt, vs, l.program));
				}
				catch (Exception e) {
					throw new BridgeError("cannot assign argument " + i + ": " + e.getMessage());
				}
			}
		}
		return sb.append("]}").toString();
	}

	// ------------------------------------------------------------------ requests

	static BigInteger unsigned(long v) {
		return new BigInteger(Long.toUnsignedString(v));
	}

	static long parseHex64(String s, String what) throws BridgeError {
		String h = s;
		if (h.startsWith("0x") || h.startsWith("0X")) {
			h = h.substring(2);
		}
		if (h.isEmpty() || h.length() > 16) {
			throw new BridgeError(what + " must be a hex string up to 64 bits, got \"" + s + "\"");
		}
		for (int i = 0; i < h.length(); i++) {
			if (Character.digit(h.charAt(i), 16) < 0) {
				throw new BridgeError(what + " must be a hex string, got \"" + s + "\"");
			}
		}
		return Long.parseUnsignedLong(h, 16);
	}

	static byte[] parseBytes(String s) throws BridgeError {
		if (s.isEmpty() || s.length() % 2 != 0) {
			throw new BridgeError("bytes must be non-empty hex of even length");
		}
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hi = Character.digit(s.charAt(2 * i), 16), lo = Character.digit(s.charAt(2 * i + 1), 16);
			if (hi < 0 || lo < 0) {
				throw new BridgeError("bytes must be hex");
			}
			b[i] = (byte) (hi << 4 | lo);
		}
		return b;
	}

	/** Strict request parser: exact field names, no duplicates, no unknown fields, strings only. */
	static Request parseRequest(String line) throws BridgeError {
		try {
			JsonReader r = new JsonReader(new StringReader(line));
			r.setStrictness(Strictness.STRICT);
			Request req = new Request();
			Set<String> seen = new HashSet<>();
			r.beginObject();
			while (r.hasNext()) {
				String name = r.nextName();
				if (!seen.add(name)) {
					throw new BridgeError("duplicate field \"" + name + "\"");
				}
				switch (name) {
					case "language":
						req.language = nextString(r, "language");
						if (req.language.isEmpty()) {
							throw new BridgeError("field \"language\" is empty");
						}
						break;
					case "batch":
						req.batch = parseBatch(r);
						break;
					default:
						throw new BridgeError("unknown field \"" + name + "\"");
				}
			}
			r.endObject();
			if (r.peek() != JsonToken.END_DOCUMENT) {
				throw new BridgeError("trailing data after the request");
			}
			if (req.language == null) {
				throw new BridgeError("missing required field \"language\"");
			}
			if (req.batch == null) {
				throw new BridgeError("missing required field \"batch\"");
			}
			if (req.batch.isEmpty()) {
				throw new BridgeError("field \"batch\" is empty");
			}
			return req;
		}
		catch (BridgeError e) {
			throw e;
		}
		catch (Exception e) {
			throw new BridgeError(e.getMessage());
		}
	}

	static String nextString(JsonReader r, String field) throws Exception {
		if (r.peek() != JsonToken.STRING) {
			throw new BridgeError("field \"" + field + "\" must be a string");
		}
		return r.nextString();
	}

	static List<Entry> parseBatch(JsonReader r) throws Exception {
		List<Entry> batch = new ArrayList<>();
		r.beginArray();
		while (r.hasNext()) {
			int i = batch.size();
			Entry e = new Entry();
			Set<String> seen = new HashSet<>();
			r.beginObject();
			while (r.hasNext()) {
				String name = r.nextName();
				if (!seen.add(name)) {
					throw new BridgeError("batch[" + i + "]: duplicate field \"" + name + "\"");
				}
				switch (name) {
					case "addr":
						e.addr = parseHex64(nextString(r, "addr"), "batch[" + i + "] addr");
						break;
					case "bytes":
						e.bytes = parseBytes(nextString(r, "bytes"));
						break;
					case "context":
						e.context = parseHex64(nextString(r, "context"), "batch[" + i + "] context");
						break;
					default:
						throw new BridgeError("batch[" + i + "]: unknown field \"" + name + "\"");
				}
			}
			r.endObject();
			for (String f : new String[] { "addr", "bytes", "context" }) {
				if (!seen.contains(f)) {
					throw new BridgeError("batch[" + i + "]: missing required field \"" + f + "\"");
				}
			}
			batch.add(e);
		}
		r.endArray();
		return batch;
	}

	// ------------------------------------------------------------------ decoding

	static void serve(Request req) {
		Lang lang = null;
		String langError = null;
		try {
			lang = language(req.language);
		}
		catch (BridgeError e) {
			langError = e.getMessage();
		}
		for (Entry e : req.batch) {
			String line;
			try {
				if (lang == null) {
					throw new BridgeError(langError);
				}
				line = decode(lang, e);
			}
			catch (BridgeError ex) {
				line = "{\"error\":" + quote(ex.getMessage()) + "}";
			}
			catch (Throwable ex) {
				line = "{\"error\":" + quote("internal error: " + ex) + "}";
			}
			out.println(line);
		}
	}

	/** The FlowType name and indirect flag the contract carries for a Ghidra FlowType name. */
	static String[] normalizeFlow(String name) throws BridgeError {
		switch (name) {
			case "FALL_THROUGH":
			case "UNCONDITIONAL_JUMP":
			case "CONDITIONAL_JUMP":
			case "UNCONDITIONAL_CALL":
			case "CONDITIONAL_CALL":
			case "TERMINATOR":
			case "CONDITIONAL_TERMINATOR":
				return new String[] { name, "false" };
			case "COMPUTED_JUMP":
				return new String[] { "UNCONDITIONAL_JUMP", "true" };
			case "CONDITIONAL_COMPUTED_JUMP":
				return new String[] { "CONDITIONAL_JUMP", "true" };
			case "COMPUTED_CALL":
				return new String[] { "UNCONDITIONAL_CALL", "true" };
			case "CONDITIONAL_COMPUTED_CALL":
				return new String[] { "CONDITIONAL_CALL", "true" };
			default:
				throw new BridgeError("FlowType " + name + " has no mapping in the contract " +
					"(bridge rule: only the table's names and the COMPUTED_* forms are emitted)");
		}
	}

	static String decode(Lang l, Entry e) throws Exception {
		Language lang = l.language;
		ProgramDB program = l.program;
		AddressSpace space = lang.getDefaultSpace();
		if (l.contextReg == null && e.context != 0) {
			throw new BridgeError("language " + lang.getLanguageID() + " has no context register");
		}
		if (l.contextReg != null && l.contextReg.getBitLength() > 64) {
			throw new BridgeError("context register " + l.contextReg + " is wider than 64 bits");
		}
		Address addr;
		try {
			addr = space.getAddress(e.addr);
		}
		catch (Exception ex) {
			throw new BridgeError("address 0x" + Long.toHexString(e.addr) + " is outside the " +
				space.getName() + " space of " + lang.getLanguageID());
		}
		// Everything happens in a transaction that is rolled back, so every entry
		// starts from the same empty program.
		int tx = program.startTransaction("decode");
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock("entry", addr,
				new ByteArrayInputStream(e.bytes), e.bytes.length, TaskMonitor.DUMMY, false);
			block.setExecute(true);
			RegisterValue ctx = null;
			if (l.contextReg != null) {
				ctx = new RegisterValue(l.contextReg, unsigned(e.context));
			}
			StringBuilder messages = new StringBuilder();
			Disassembler dis = Disassembler.getDisassembler(program, TaskMonitor.DUMMY,
				m -> messages.append(m));
			dis.disassemble(addr, new AddressSet(block.getStart(), block.getEnd()), ctx, false);
			Instruction ins = program.getListing().getInstructionAt(addr);
			if (ins == null) {
				String why = messages.length() > 0 ? ": " + messages.toString().trim() : "";
				throw new BridgeError("no instruction at 0x" + Long.toHexString(e.addr) + why);
			}
			String[] flow = normalizeFlow(ins.getFlowType().toString());
			long used = 0;
			if (l.contextReg != null) {
				RegisterValue rv = program.getProgramContext().getRegisterValue(l.contextReg, addr);
				used = rv == null ? 0 : rv.getUnsignedValueIgnoreMask().longValue();
			}
			StringBuilder sb = new StringBuilder();
			sb.append("{\"addr\":").append(hex(e.addr));
			sb.append(",\"len\":").append(ins.getLength());
			sb.append(",\"mnemonic\":").append(quote(ins.getMnemonicString()));
			sb.append(",\"text\":").append(quote(ins.toString()));
			sb.append(",\"flow\":").append(quote(flow[0]));
			sb.append(",\"has_fallthrough\":").append(ins.hasFallthrough());
			sb.append(",\"targets\":[");
			boolean indirect = flow[1].equals("true");
			if (!indirect) {
				boolean first = true;
				for (Address t : ins.getFlows()) {
					if (!first) {
						sb.append(',');
					}
					first = false;
					sb.append(hex(t.getOffset()));
				}
			}
			sb.append("],\"indirect\":").append(indirect);
			sb.append(",\"context\":").append(hex(used)).append('}');
			return sb.toString();
		}
		finally {
			program.endTransaction(tx, false);
		}
	}

	// ------------------------------------------------------------------ JSON output

	static String quote(String s) {
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					sb.append("\\\"");
					break;
				case '\\':
					sb.append("\\\\");
					break;
				case '\n':
					sb.append("\\n");
					break;
				case '\r':
					sb.append("\\r");
					break;
				case '\t':
					sb.append("\\t");
					break;
				default:
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
			}
		}
		return sb.append('"').toString();
	}
}

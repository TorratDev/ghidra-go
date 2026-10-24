// Dump the open program to JSON plus a binary sidecar (memory block bytes), read-only.
//
// Usage: analyzeHeadless <projdir> <project> -process <program> -readOnly -noanalysis \
//          -scriptPath scripts/export -postScript ExportProject.java <outdir>
// Writes <outdir>/export.json and <outdir>/export.bin (default outdir: the current directory).
// Further script args are hex addresses (ram space) at which tracked_context checks that a register's
// value is constant over its whole range.
// Compiled by Ghidra against its own jars; written for Ghidra 11.4.3.
// @category Export

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

public class ExportProject extends GhidraScript {
	private static final int FORMAT_VERSION = 1; // layout of export.json; the Go reader rejects other values
	private static final int CHUNK = 1 << 20;
	private static final long CHECK_LIMIT = 4_000_000; // addresses walked per tracked_context range check

	private PrintWriter out;
	private final Map<String, DataType> types = new TreeMap<>(); // keyed by path name, so output is sorted
	private final Set<String> visited = new HashSet<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File dir = new File(args.length > 0 ? args[0] : ".");
		dir.mkdirs();
		File binFile = new File(dir, "export.bin");
		File jsonFile = new File(dir, "export.json");

		List<MemoryBlock> blocks = new ArrayList<>(Arrays.asList(currentProgram.getMemory().getBlocks()));
		blocks.sort(Comparator.comparing(MemoryBlock::getStart)); // javadoc gives no order
		Map<MemoryBlock, long[]> placed = new HashMap<>(); // block -> {file offset, length}
		String sidecarSha = writeSidecar(binFile, blocks, placed);

		try (PrintWriter w = new PrintWriter(new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(jsonFile), StandardCharsets.UTF_8), 1 << 16))) {
			out = w;
			out.print("{\n");
			writeProgram(binFile, sidecarSha);
			out.print(",\n\"memory_blocks\": ");
			writeBlocks(blocks, placed);
			out.print(",\n\"symbols\": ");
			writeSymbols();
			out.print(",\n\"functions\": ");
			writeFunctions();
			// Every section that calls typeRef() must come before data_types.
			out.print(",\n\"instructions\": ");
			writeInstructions();
			out.print(",\n\"context\": ");
			writeContext();
			out.print(",\n\"registers\": ");
			writeRegisters();
			out.print(",\n\"userops\": ");
			writeUserOps();
			out.print(",\n\"tracked_context\": ");
			writeTrackedContext(args);
			out.print(",\n\"comments\": ");
			writeComments();
			out.print(",\n\"defined_data\": ");
			writeDefinedData();
			out.print(",\n\"data_types\": ");
			writeTypes();
			out.print("\n}\n");
		}
		println("export: wrote " + jsonFile + " and " + binFile);
	}

	// Initialized blocks only, in address order, in chunks.
	private String writeSidecar(File f, List<MemoryBlock> blocks, Map<MemoryBlock, long[]> placed)
			throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		long pos = 0;
		byte[] buf = new byte[CHUNK];
		try (OutputStream os = new BufferedOutputStream(new FileOutputStream(f))) {
			for (MemoryBlock b : blocks) {
				if (!b.isInitialized()) {
					continue;
				}
				long size = b.getSize();
				for (long done = 0; done < size; ) {
					monitor.checkCancelled();
					int n = (int) Math.min(CHUNK, size - done);
					int got = b.getBytes(b.getStart().add(done), buf, 0, n);
					if (got != n) {
						throw new IOException("short read in block " + b.getName() + " at +" + done);
					}
					os.write(buf, 0, n);
					md.update(buf, 0, n);
					done += n;
				}
				placed.put(b, new long[] { pos, size });
				pos += size;
			}
		}
		return hex(md.digest());
	}

	private void writeProgram(File bin, String sha) {
		out.print("\"format_version\": " + FORMAT_VERSION);
		out.print(",\n\"project\": " + q(state.getProject() == null ? null : state.getProject().getName()));
		out.print(",\n\"program\": " + q(currentProgram.getName()));
		out.print(",\n\"ghidra_version\": " + q(Application.getApplicationVersion()));
		out.print(",\n\"language\": " + q(currentProgram.getLanguageID().getIdAsString()));
		out.print(",\n\"compiler_spec\": " + q(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()));
		out.print(",\n\"image_base\": " + q(currentProgram.getImageBase().toString(true)));
		out.print(",\n\"executable_md5\": " + q(currentProgram.getExecutableMD5()));
		out.print(",\n\"function_count\": " + currentProgram.getFunctionManager().getFunctionCount());
		out.print(",\n\"sidecar\": {\"file\": " + q(bin.getName()) + ", \"sha256\": " + q(sha) + "}");
	}

	private void writeBlocks(List<MemoryBlock> blocks, Map<MemoryBlock, long[]> placed) {
		out.print("[");
		String sep = "\n";
		for (MemoryBlock b : blocks) {
			out.print(sep);
			sep = ",\n";
			out.print("{\"name\": " + q(b.getName()) + ", \"start\": " + q(b.getStart().toString(true)) +
				", \"size\": " + b.getSize() +
				", \"read\": " + b.isRead() + ", \"write\": " + b.isWrite() + ", \"execute\": " + b.isExecute() +
				", \"type\": " + q(b.getType().toString()) +
				", \"initialized\": " + b.isInitialized() + ", \"volatile\": " + b.isVolatile() +
				", \"overlay\": " + b.isOverlay());
			long[] p = placed.get(b);
			out.print(p == null ? ", \"sidecar_offset\": null, \"sidecar_length\": null"
				: ", \"sidecar_offset\": " + p[0] + ", \"sidecar_length\": " + p[1]);
			out.print("}");
		}
		out.print("\n]");
	}

	private void writeSymbols() throws Exception {
		List<Symbol> syms = new ArrayList<>();
		SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s == null) { // next() returns null at the end
				break;
			}
			syms.add(s);
		}
		syms.sort(Comparator.<Symbol, Integer>comparing(s -> s.getAddress() == Address.NO_ADDRESS ? 0 : 1)
			.thenComparing((Symbol s) -> s.getAddress())
			.thenComparing((Symbol s) -> s.getName())
			.thenComparingInt(s -> s.getSymbolType().getID())
			.thenComparing((Symbol s) -> String.join("::", s.getPath())));
		out.print("[");
		String sep = "\n";
		for (Symbol s : syms) {
			monitor.checkCancelled();
			out.print(sep);
			sep = ",\n";
			out.print("{\"name\": " + q(s.getName()) + ", \"address\": " + addr(s.getAddress()) +
				", \"type_id\": " + s.getSymbolType().getID() + ", \"type\": " + q(s.getSymbolType().toString()) +
				", \"namespace\": " + nsPath(s.getParentNamespace()) +
				", \"source\": " + q(s.getSource().toString()) + ", \"primary\": " + s.isPrimary() + "}");
		}
		out.print("\n]");
	}

	private void writeFunctions() throws Exception {
		out.print("[");
		String sep = "\n";
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true); // ascending address
		while (it.hasNext()) {
			monitor.checkCancelled();
			Function f = it.next();
			out.print(sep);
			sep = ",\n";
			out.print("{\"entry\": " + addr(f.getEntryPoint()) + ", \"name\": " + q(f.getName()) +
				", \"namespace\": " + nsPath(f.getParentNamespace()) +
				", \"calling_convention\": " + q(f.getCallingConventionName()) +
				", \"thunk\": " + f.isThunk() + ", \"varargs\": " + f.hasVarArgs() +
				", \"no_return\": " + f.hasNoReturn() + ", \"custom_storage\": " + f.hasCustomVariableStorage() +
				", \"body\": [");
			String rs = "";
			for (AddressRange r : f.getBody().getAddressRanges()) {
				out.print(rs + "{\"start\": " + addr(r.getMinAddress()) + ", \"end\": " + addr(r.getMaxAddress()) + "}");
				rs = ", ";
			}
			out.print("], \"prototype\": " + q(f.getPrototypeString(true, true)) + callingModelFields(f) +
				", \"return_type\": " + typeRef(f.getReturnType()) + ", \"return_storage\": " + q(f.getReturn().getVariableStorage().toString()) +
				", \"parameters\": [");
			rs = "";
			for (Parameter p : f.getParameters()) {
				out.print(rs + "{\"ordinal\": " + p.getOrdinal() + ", \"name\": " + q(p.getName()) +
					", \"data_type\": " + typeRef(p.getDataType()) + ", \"storage\": " + q(p.getVariableStorage().toString()) + "}");
				rs = ", ";
			}
			out.print("], \"local_variables\": [");
			rs = "";
			for (Variable v : f.getLocalVariables()) {
				out.print(rs + "{\"name\": " + q(v.getName()) + ", \"data_type\": " + typeRef(v.getDataType()) +
					", \"length\": " + v.getLength() + ", \"storage\": " + q(v.getVariableStorage().toString()) +
					", \"stack_offset\": " + (v.isStackVariable() ? String.valueOf(v.getStackOffset()) : "null") +
					", \"first_use_offset\": " + v.getFirstUseOffset() + "}");
				rs = ", ";
			}
			out.print("]}");
		}
		out.print("\n]");
	}

	// Purge, stackshift and extrapop the way FunctionPrototype.grabFromFunction computes them: the
	// function's own model, else the compiler spec default (the decompiler never sees a null model).
	private String callingModelFields(Function f) {
		int purge = f.getStackPurgeSize();
		boolean purgeValid = purge != Function.INVALID_STACK_DEPTH_CHANGE && purge != Function.UNKNOWN_STACK_DEPTH_CHANGE;
		PrototypeModel pm = f.getCallingConvention();
		boolean explicit = pm != null;
		if (pm == null) {
			pm = currentProgram.getCompilerSpec().getDefaultCallingConvention();
		}
		String extrapop = pm == null ? "null" : String.valueOf(purgeValid ? purge + pm.getStackshift() : pm.getExtrapop());
		return ", \"calling_convention_explicit\": " + explicit +
			", \"stack_purge_size\": " + (purgeValid ? String.valueOf(purge) : "null") +
			", \"stackshift\": " + (pm == null ? "null" : String.valueOf(pm.getStackshift())) +
			", \"cc_extrapop\": " + (pm == null ? "null" : String.valueOf(pm.getExtrapop())) +
			", \"extrapop\": " + extrapop;
	}

	// Listing instructions only. Code the decompiler disassembles on the fly (pseudoDisassemble) is not recorded.
	private void writeInstructions() throws Exception {
		out.print("[");
		String sep = "\n";
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction ins = it.next();
			out.print(sep);
			sep = ",\n";
			byte[] bytes = null;
			try {
				bytes = ins.getBytes();
			}
			catch (MemoryAccessException e) {
				// leave null
			}
			out.print("{\"address\": " + addr(ins.getAddress()) + ", \"length\": " + ins.getLength() +
				", \"parsed_length\": " + ins.getParsedLength() + ", \"length_overridden\": " + ins.isLengthOverridden() +
				", \"mnemonic\": " + q(ins.getMnemonicString()) + ", \"bytes\": " + (bytes == null ? "null" : "\"" + hexs(bytes) + "\"") +
				", \"flow_override\": " + q(ins.getFlowOverride().name()) +
				", \"fallthrough\": " + addr(ins.getFallThrough()) + ", \"default_fallthrough\": " + addr(ins.getDefaultFallThrough()) +
				", \"fallthrough_overridden\": " + ins.isFallThroughOverridden() +
				", \"delay_slot_depth\": " + ins.getDelaySlotDepth() + ", \"in_delay_slot\": " + ins.isInDelaySlot() +
				", \"references_from\": [");
			Reference[] refs = ins.getReferencesFrom();
			Arrays.sort(refs, Comparator.<Reference, Integer>comparing(r -> r.getOperandIndex())
				.thenComparing((Reference r) -> r.getToAddress())
				.thenComparing((Reference r) -> r.getReferenceType().getName())
				.thenComparing((Reference r) -> r.isPrimary()));
			String rs = "";
			for (Reference r : refs) {
				out.print(rs + "{\"from\": " + addr(r.getFromAddress()) + ", \"to\": " + addr(r.getToAddress()) +
					", \"type\": " + q(r.getReferenceType().getName()) + ", \"primary\": " + r.isPrimary() +
					", \"operand_index\": " + r.getOperandIndex() + ", \"source\": " + q(r.getSource().toString()) + "}");
				rs = ", ";
			}
			out.print("]}");
		}
		out.print("\n]");
	}

	private void writeContext() throws Exception {
		ProgramContext pc = currentProgram.getProgramContext();
		List<Register> regs = new ArrayList<>(pc.getContextRegisters());
		regs.sort(Comparator.comparing((Register r) -> r.getName()));
		out.print("{\"registers\": [");
		String sep = "";
		for (Register r : regs) {
			out.print(sep + "{\"name\": " + q(r.getName()) + ", \"bit_length\": " + r.getBitLength() + "}");
			sep = ", ";
		}
		RegisterValue dv = pc.getDefaultDisassemblyContext();
		out.print("], \"default_disassembly_context\": " + (dv == null ? "null" :
			"{\"register\": " + q(dv.getRegister().getName()) + ", \"value\": " + q(big(dv.getUnsignedValueIgnoreMask())) +
				", \"mask\": " + q(big(dv.getValueMask())) + "}"));
		out.print(", \"ranges\": [");
		sep = "\n";
		for (Register r : regs) {
			AddressRangeIterator it = pc.getRegisterValueAddressRanges(r);
			while (it.hasNext()) {
				monitor.checkCancelled();
				AddressRange ar = it.next();
				RegisterValue rv = pc.getRegisterValue(r, ar.getMinAddress());
				out.print(sep + "{\"register\": " + q(r.getName()) + ", \"start\": " + addr(ar.getMinAddress()) +
					", \"end\": " + addr(ar.getMaxAddress()) + ", \"value\": " +
					(rv == null ? "null" : q(big(rv.getUnsignedValueIgnoreMask())) + ", \"mask\": " + q(big(rv.getValueMask()))) + "}");
				sep = ",\n";
			}
		}
		out.print("\n]}");
	}

	private void writeRegisters() {
		List<Register> regs = new ArrayList<>(currentProgram.getLanguage().getRegisters());
		regs.sort(Comparator.comparing((Register r) -> r.getName()));
		out.print("[");
		String sep = "\n";
		for (Register r : regs) {
			out.print(sep + regJson(r) + "}");
			sep = ",\n";
		}
		out.print("\n]");
	}

	// Register fields without the closing brace, so callers can append.
	private static String regJson(Register r) {
		AddressSpace sp = r.getAddress().getAddressSpace();
		return "{\"name\": " + q(r.getName()) + ", \"space\": " + q(sp.getName()) + ", \"space_id\": " + sp.getSpaceID() +
			", \"offset\": " + r.getAddress().getOffset() + ", \"size\": " + r.getMinimumByteSize() +
			", \"processor_context\": " + r.isProcessorContext();
	}

	private void writeUserOps() {
		int n = currentProgram.getLanguage().getNumberOfUserDefinedOpNames();
		out.print("[");
		String sep = "\n";
		for (int i = 0; i < n; i++) {
			out.print(sep + "{\"index\": " + i + ", \"name\": " + q(currentProgram.getLanguage().getUserDefinedOpName(i)) + "}");
			sep = ",\n";
		}
		out.print("\n]");
	}

	// Non-context registers with explicitly set values: the ranges of constant value. For each address given as a script
	// arg, the range containing it is walked address by address (at most CHECK_LIMIT addresses; "complete"
	// says whether that covered the range) to check the value never changes.
	private void writeTrackedContext(String[] args) throws Exception {
		ProgramContext pc = currentProgram.getProgramContext();
		List<Register> regs = new ArrayList<>();
		for (Register r : pc.getRegisters()) {
			if (!r.isProcessorContext()) {
				regs.add(r);
			}
		}
		regs.sort(Comparator.comparing((Register r) -> r.getName()));
		List<Address> probes = new ArrayList<>();
		for (int i = 1; i < args.length; i++) {
			probes.add(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(args[i], 16)));
		}
		StringBuilder checks = new StringBuilder();
		out.print("{\"registers\": [");
		String sep = "\n";
		for (Register r : regs) {
			AddressRangeIterator it = pc.getRegisterValueAddressRanges(r);
			if (!it.hasNext()) {
				continue;
			}
			out.print(sep + regJson(r) + ", \"ranges\": [");
			sep = ",\n";
			String rs = "";
			while (it.hasNext()) {
				monitor.checkCancelled();
				AddressRange ar = it.next();
				BigInteger v = pc.getValue(r, ar.getMinAddress(), false);
				out.print(rs + "{\"start\": " + addr(ar.getMinAddress()) + ", \"end\": " + addr(ar.getMaxAddress()) +
					", \"value\": " + q(big(v)) + "}");
				rs = ", ";
				for (Address p : probes) {
					if (!ar.contains(p)) {
						continue;
					}
					long checked = 0;
					boolean uniform = true;
					for (Address a = ar.getMinAddress(); a != null && ar.contains(a) && checked < CHECK_LIMIT; a = a.next()) {
						monitor.checkCancelled();
						if (!Objects.equals(pc.getValue(r, a, false), v)) {
							uniform = false;
						}
						checked++;
					}
					checks.append(checks.length() > 0 ? ", " : "").append("{\"address\": " + addr(p) + ", \"register\": " + q(r.getName()) +
						", \"range_start\": " + addr(ar.getMinAddress()) + ", \"range_end\": " + addr(ar.getMaxAddress()) +
						", \"addresses_checked\": " + checked + ", \"complete\": " + (ar.getLength() <= CHECK_LIMIT) +
						", \"uniform\": " + uniform + "}");
					println("tracked_context: " + r.getName() + " over " + ar + " containing " + p + " uniform=" + uniform);
				}
			}
			out.print("]}");
		}
		out.print("\n], \"uniform_check\": [" + checks + "], \"entries\": [");
		// What DecompileCallback.encodeTrackedPointSet asks: every non-context register's value at one
		// address, including the language default (which getRegisterValueAddressRanges does not report).
		// Asked here at each function entry; registers with no value are left out, as there.
		sep = "\n";
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
		while (fit.hasNext()) {
			monitor.checkCancelled();
			Address entry = fit.next().getEntryPoint();
			out.print(sep + "{\"entry\": " + addr(entry) + ", \"values\": [");
			sep = ",\n";
			String vs = "";
			for (Register r : regs) {
				BigInteger v = pc.getValue(r, entry, false);
				if (v != null) {
					out.print(vs + regJson(r) + ", \"value\": " + q(big(v)) + "}");
					vs = ", ";
				}
			}
			out.print("]}");
		}
		out.print("\n]}");
	}

	private void writeComments() throws Exception {
		Listing listing = currentProgram.getListing();
		AddressSetView set = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
		List<Object[]> found = new ArrayList<>(); // {Address, CommentType, String}
		for (CommentType ct : new CommentType[] { CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE,
			CommentType.REPEATABLE }) {
			AddressIterator it = listing.getCommentAddressIterator(ct, set, true);
			while (it.hasNext()) {
				monitor.checkCancelled();
				Address a = it.next();
				String text = listing.getComment(ct, a);
				if (text != null) {
					found.add(new Object[] { a, ct, text });
				}
			}
		}
		found.sort(Comparator.<Object[], Address>comparing(o -> (Address) o[0]).thenComparingInt(o -> ((CommentType) o[1]).ordinal()));
		out.print("[");
		String sep = "\n";
		for (Object[] o : found) {
			out.print(sep + "{\"address\": " + addr((Address) o[0]) + ", \"type\": " + q(((CommentType) o[1]).name()) +
				", \"text\": " + q((String) o[2]) + "}");
			sep = ",\n";
		}
		out.print("\n]");
	}

	// Component coverage of structures/arrays at these addresses is not checked.
	private void writeDefinedData() throws Exception {
		out.print("[");
		String sep = "\n";
		DataIterator it = currentProgram.getListing().getDefinedData(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Data d = it.next();
			out.print(sep + "{\"address\": " + addr(d.getAddress()) + ", \"data_type\": " + typeRef(d.getDataType()) +
				", \"length\": " + d.getLength() + "}");
			sep = ",\n";
		}
		out.print("\n]");
	}

	private static String big(BigInteger v) {
		return v == null ? null : v.toString();
	}

	private static String hexs(byte[] b) {
		char[] c = new char[b.length * 2];
		for (int i = 0; i < b.length; i++) {
			c[2 * i] = "0123456789abcdef".charAt((b[i] >> 4) & 0xf);
			c[2 * i + 1] = "0123456789abcdef".charAt(b[i] & 0xf);
		}
		return new String(c);
	}

	// A reference is the data type's path name; the definition goes into the data_types table.
	private String typeRef(DataType dt) {
		collect(dt);
		return q(dt.getPathName());
	}

	private void collect(DataType dt) {
		if (dt == null || !visited.add(dt.getPathName())) {
			return;
		}
		types.put(dt.getPathName(), dt);
		if (dt instanceof TypeDef) {
			collect(((TypeDef) dt).getBaseDataType());
		}
		else if (dt instanceof Pointer) {
			collect(((Pointer) dt).getDataType());
		}
		else if (dt instanceof Array) {
			collect(((Array) dt).getDataType());
		}
		else if (dt instanceof Composite) {
			for (DataTypeComponent c : ((Composite) dt).getDefinedComponents()) {
				collect(c.getDataType());
			}
		}
		else if (dt instanceof FunctionDefinition) {
			FunctionDefinition fd = (FunctionDefinition) dt;
			collect(fd.getReturnType());
			for (ParameterDefinition p : fd.getArguments()) {
				collect(p.getDataType());
			}
		}
	}

	private void writeTypes() {
		out.print("[");
		String sep = "\n";
		for (DataType dt : types.values()) {
			out.print(sep);
			sep = ",\n";
			// No universal ID: Ghidra generates a new one per session for types it creates on the fly
			// (e.g. "undefined"), which would make two exports differ.
			out.print("{\"name\": " + q(dt.getName()) + ", \"path_name\": " + q(dt.getPathName()) +
				", \"category_path\": " + q(dt.getCategoryPath().getPath()) + ", \"length\": " + dt.getLength() +
				", \"alignment\": " + dt.getAlignment() + ", \"description\": " + q(dt.getDescription()) +
				", \"kind\": " + q(kind(dt)));
			if (dt instanceof TypeDef) {
				out.print(", \"base\": " + q(((TypeDef) dt).getBaseDataType().getPathName()));
			}
			else if (dt instanceof Pointer) {
				DataType t = ((Pointer) dt).getDataType();
				out.print(", \"base\": " + (t == null ? "null" : q(t.getPathName())));
			}
			else if (dt instanceof Array) {
				Array a = (Array) dt;
				out.print(", \"base\": " + q(a.getDataType().getPathName()) + ", \"elements\": " + a.getNumElements() +
					", \"element_length\": " + a.getElementLength());
			}
			else if (dt instanceof Composite) {
				out.print(", \"components\": [");
				String cs = "";
				for (DataTypeComponent c : ((Composite) dt).getDefinedComponents()) {
					out.print(cs + "{\"ordinal\": " + c.getOrdinal() + ", \"offset\": " + c.getOffset() +
						", \"name\": " + q(c.getFieldName()) + ", \"data_type\": " + q(c.getDataType().getPathName()) +
						", \"length\": " + c.getLength() + "}");
					cs = ", ";
				}
				out.print("]");
			}
			else if (dt instanceof FunctionDefinition) {
				FunctionDefinition fd = (FunctionDefinition) dt;
				out.print(", \"return_type\": " + q(fd.getReturnType().getPathName()) + ", \"parameters\": [");
				String ps = "";
				for (ParameterDefinition p : fd.getArguments()) {
					out.print(ps + "{\"ordinal\": " + p.getOrdinal() + ", \"name\": " + q(p.getName()) +
						", \"data_type\": " + q(p.getDataType().getPathName()) + "}");
					ps = ", ";
				}
				out.print("]");
			}
			out.print("}");
		}
		out.print("\n]");
	}

	private static String kind(DataType dt) {
		for (Class<?> c : new Class<?>[] { TypeDef.class, Pointer.class, Array.class, Structure.class, Union.class,
			FunctionDefinition.class, ghidra.program.model.data.Enum.class }) {
			if (c.isInstance(dt)) {
				return c.getSimpleName();
			}
		}
		return "Other";
	}

	private static String addr(Address a) {
		return a == null || a == Address.NO_ADDRESS ? "null" : q(a.toString(true));
	}

	// Namespace path from the outermost namespace down; the global namespace is the empty list.
	private static String nsPath(Namespace ns) {
		Deque<String> names = new ArrayDeque<>();
		for (; ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
			names.addFirst(ns.getName());
		}
		StringBuilder sb = new StringBuilder("[");
		for (String n : names) {
			sb.append(sb.length() > 1 ? ", " : "").append(q(n));
		}
		return sb.append("]").toString();
	}

	private static String q(String s) {
		if (s == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"': sb.append("\\\""); break;
				case '\\': sb.append("\\\\"); break;
				case '\n': sb.append("\\n"); break;
				case '\r': sb.append("\\r"); break;
				case '\t': sb.append("\\t"); break;
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

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02x", x));
		}
		return sb.toString();
	}
}

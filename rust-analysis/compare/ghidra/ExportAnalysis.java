/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Exports Ghidra's auto-analysis results in the normalized JSON schema used by
// rust-analysis (`ra compare`). Run headless as a post-script:
//   analyzeHeadless <projDir> <proj> -import <bin> -scriptPath <dir>
//       -postScript ExportAnalysis.java <out.json> -deleteProject
//@category Analysis

import java.io.FileWriter;
import java.io.Writer;
import java.util.*;

import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

public class ExportAnalysis extends GhidraScript {

	private static String hex(Address a) {
		return "0x" + Long.toHexString(a.getOffset());
	}

	private static String source(SourceType s) {
		switch (s) {
			case IMPORTED:
				return "imported";
			case ANALYSIS:
				return "analysis";
			case DEFAULT:
				return "default";
			default:
				return "user";
		}
	}

	/**
	 * Namespace path of a symbol below its library (externals) or the global
	 * namespace, e.g. {@code std::vector<int>}; null when there is none.
	 */
	private static String namespaceOf(Symbol s) {
		List<String> parts = new ArrayList<>();
		Namespace ns = s.getParentNamespace();
		while (ns != null && !ns.isGlobal() && !(ns instanceof Library)) {
			parts.add(0, ns.getName());
			ns = ns.getParentNamespace();
		}
		return parts.isEmpty() ? null : String.join("::", parts);
	}

	private static String libraryOf(Symbol s) {
		Namespace ns = s.getParentNamespace();
		while (ns != null && !ns.isGlobal()) {
			if (ns instanceof Library) {
				return ns.getName();
			}
			ns = ns.getParentNamespace();
		}
		return null;
	}

	private static void writeNamespace(JsonWriter w, Symbol s) throws Exception {
		String ns = namespaceOf(s);
		if (ns == null) {
			w.name("namespace").nullValue();
		}
		else {
			w.name("namespace").value(ns);
		}
	}

	private boolean inMemory(Address a) {
		return a != null && a.isMemoryAddress() && !a.isExternalAddress() &&
			currentProgram.getMemory().contains(a) && !isArtificial(a);
	}

	private boolean isArtificial(Address a) {
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		return b == null || !b.isLoaded() || b.getName().equals("EXTERNAL");
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: ExportAnalysis.java <out.json>");
		}
		try (Writer fw = new FileWriter(args[0]); JsonWriter w = new JsonWriter(fw)) {
			w.setIndent(" ");
			w.beginObject();
			w.name("schema_version").value(2);
			w.name("producer").value("ghidra " + Application.getApplicationVersion());
			writeBinary(w);
			writeMemory(w);
			writeSymbols(w);
			writeImports(w);
			writeExports(w);
			writeFunctions(w);
			writeInstructions(w);
			writeBlocks(w);
			writeXrefs(w);
			w.endObject();
		}
	}

	private void writeBinary(JsonWriter w) throws Exception {
		w.name("binary").beginObject();
		w.name("path").value(currentProgram.getName());
		String sha = currentProgram.getExecutableSHA256();
		w.name("sha256").value(sha == null ? "" : sha);
		String fmt = currentProgram.getExecutableFormat();
		String norm = fmt.contains("ELF") ? "ELF"
				: fmt.contains("PE") ? "PE"
				: fmt.contains("Mach-O") ? "MachO"
				: fmt.contains("Raw") ? "Raw" : fmt;
		w.name("format").value(norm);
		w.name("language").value(currentProgram.getLanguageID().getIdAsString());
		w.name("image_base").value(hex(currentProgram.getImageBase()));
		w.endObject();
	}

	private void writeMemory(JsonWriter w) throws Exception {
		w.name("memory").beginArray();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (!b.isLoaded() || b.getName().equals("EXTERNAL") ||
				!b.getStart().isMemoryAddress()) {
				continue;
			}
			w.beginObject();
			w.name("name").value(b.getName());
			w.name("start").value(hex(b.getStart()));
			w.name("end").value("0x" + Long.toHexString(b.getEnd().getOffset() + 1));
			w.name("read").value(b.isRead());
			w.name("write").value(b.isWrite());
			w.name("execute").value(b.isExecute());
			w.name("initialized").value(b.isInitialized());
			w.endObject();
		}
		w.endArray();
	}

	private void writeSymbols(JsonWriter w) throws Exception {
		w.name("symbols").beginArray();
		SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
		Listing listing = currentProgram.getListing();
		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			if (s.isExternal() || !inMemory(s.getAddress())) {
				continue;
			}
			SymbolType t = s.getSymbolType();
			String kind;
			if (t == SymbolType.FUNCTION) {
				kind = "function";
			}
			else if (t == SymbolType.LABEL) {
				kind = listing.getDefinedDataAt(s.getAddress()) != null ? "data" : "label";
			}
			else {
				continue;
			}
			w.beginObject();
			w.name("addr").value(hex(s.getAddress()));
			w.name("name").value(s.getName());
			writeNamespace(w, s);
			w.name("kind").value(kind);
			w.name("source").value(source(s.getSource()));
			w.endObject();
		}
		w.endArray();
	}

	private void writeImports(JsonWriter w) throws Exception {
		// Every external symbol, including those a demangler moved into a
		// child namespace of the library (getExternalLocations(lib) only
		// walks the library's direct children).
		w.name("imports").beginArray();
		ExternalManager em = currentProgram.getExternalManager();
		ReferenceManager rm = currentProgram.getReferenceManager();
		Listing listing = currentProgram.getListing();
		SymbolIterator it = currentProgram.getSymbolTable().getExternalSymbols();
		while (it.hasNext()) {
			Symbol sym = it.next();
			ExternalLocation loc = em.getExternalLocation(sym);
			if (loc == null) {
				continue;
			}
			Address slot = null;
			for (Reference r : rm.getReferencesTo(sym.getAddress())) {
				Address from = r.getFromAddress();
				if (inMemory(from) && listing.getInstructionAt(from) == null) {
					slot = from;
					break;
				}
			}
			if (slot == null && loc.getFunction() != null) {
				Address[] thunks = loc.getFunction().getFunctionThunkAddresses(false);
				if (thunks != null && thunks.length > 0) {
					slot = thunks[0];
				}
			}
			String lib = libraryOf(sym);
			w.beginObject();
			w.name("name").value(sym.getName());
			writeNamespace(w, sym);
			if (lib == null || lib.equals(Library.UNKNOWN)) {
				w.name("library").nullValue();
			}
			else {
				w.name("library").value(lib);
			}
			if (slot == null) {
				w.name("addr").nullValue();
			}
			else {
				w.name("addr").value(hex(slot));
			}
			w.endObject();
		}
		w.endArray();
	}

	private void writeExports(JsonWriter w) throws Exception {
		w.name("exports").beginArray();
		SymbolTable st = currentProgram.getSymbolTable();
		AddressIterator it = st.getExternalEntryPointIterator();
		while (it.hasNext()) {
			Address a = it.next();
			if (!inMemory(a)) {
				continue;
			}
			for (Symbol s : st.getSymbols(a)) {
				w.beginObject();
				w.name("addr").value(hex(a));
				w.name("name").value(s.getName());
				w.endObject();
			}
		}
		w.endArray();
	}

	private void writeFunctions(JsonWriter w) throws Exception {
		w.name("functions").beginArray();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!inMemory(f.getEntryPoint())) {
				continue;
			}
			w.beginObject();
			w.name("entry").value(hex(f.getEntryPoint()));
			w.name("name").value(f.getName());
			writeNamespace(w, f.getSymbol());
			w.name("source").value(source(f.getSymbol().getSource()));
			w.name("thunk").value(f.isThunk());
			Function thunked = f.isThunk() ? f.getThunkedFunction(false) : null;
			if (thunked != null && inMemory(thunked.getEntryPoint())) {
				w.name("thunk_target").value(hex(thunked.getEntryPoint()));
			}
			else {
				w.name("thunk_target").nullValue();
			}
			w.name("no_return").value(f.hasNoReturn());
			w.name("body").beginArray();
			for (AddressRange r : f.getBody()) {
				w.beginArray();
				w.value(hex(r.getMinAddress()));
				w.value("0x" + Long.toHexString(r.getMaxAddress().getOffset() + 1));
				w.endArray();
			}
			w.endArray();
			w.endObject();
		}
		w.endArray();
	}

	private void writeInstructions(JsonWriter w) throws Exception {
		w.name("instructions").beginArray();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction i = it.next();
			if (!inMemory(i.getAddress())) {
				continue;
			}
			w.beginObject();
			w.name("addr").value(hex(i.getAddress()));
			w.name("len").value(i.getLength());
			w.name("mnemonic").value(i.getMnemonicString().toUpperCase());
			w.endObject();
		}
		w.endArray();
	}

	private void writeBlocks(JsonWriter w) throws Exception {
		BasicBlockModel model = new BasicBlockModel(currentProgram);
		List<String[]> edges = new ArrayList<>();
		w.name("blocks").beginArray();
		CodeBlockIterator it = model.getCodeBlocks(monitor);
		while (it.hasNext() && !monitor.isCancelled()) {
			CodeBlock b = it.next();
			if (!inMemory(b.getFirstStartAddress())) {
				continue;
			}
			w.beginObject();
			w.name("start").value(hex(b.getFirstStartAddress()));
			w.name("end").value("0x" + Long.toHexString(b.getMaxAddress().getOffset() + 1));
			w.endObject();
			CodeBlockReferenceIterator dests = b.getDestinations(monitor);
			while (dests.hasNext()) {
				CodeBlockReference d = dests.next();
				FlowType ft = d.getFlowType();
				if (ft.isCall() || !inMemory(d.getDestinationAddress())) {
					continue;
				}
				String kind = ft.isFallthrough() ? "fallthrough"
						: ft.isConditional() ? "cond_jump" : ft.isJump() ? "jump" : null;
				if (kind == null) {
					continue;
				}
				edges.add(new String[] { hex(b.getFirstStartAddress()),
					hex(d.getDestinationAddress()), kind });
			}
		}
		w.endArray();
		w.name("edges").beginArray();
		for (String[] e : edges) {
			w.beginObject();
			w.name("from").value(e[0]);
			w.name("to").value(e[1]);
			w.name("kind").value(e[2]);
			w.endObject();
		}
		w.endArray();
	}

	private void writeXrefs(JsonWriter w) throws Exception {
		w.name("xrefs").beginArray();
		ReferenceManager rm = currentProgram.getReferenceManager();
		AddressIterator it = rm.getReferenceSourceIterator(currentProgram.getMinAddress(), true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Address from = it.next();
			if (!inMemory(from)) {
				continue;
			}
			for (Reference r : rm.getReferencesFrom(from)) {
				Address to = r.getToAddress();
				if (!inMemory(to) || r.isStackReference() || r.isRegisterReference()) {
					continue;
				}
				RefType t = r.getReferenceType();
				String kind;
				if (t.isFallthrough() || t == RefType.THUNK || t == RefType.EXTERNAL_REF) {
					continue;
				}
				else if (t.isCall()) {
					kind = "call";
				}
				else if (t.isJump()) {
					kind = t.isConditional() ? "cond_jump" : "jump";
				}
				else if (t.isWrite()) {
					kind = "write";
				}
				else if (t.isRead()) {
					kind = "read";
				}
				else {
					kind = "data";
				}
				w.beginObject();
				w.name("from").value(hex(from));
				w.name("to").value(hex(to));
				w.name("kind").value(kind);
				w.endObject();
			}
		}
		w.endArray();
	}
}

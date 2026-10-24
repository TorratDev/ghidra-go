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
// Demangle oracle for rust-analysis: runs every installed Ghidra demangler on
// each mangled name in a text file (one per line) and writes Ghidra's leaf
// name, namespace and signature as JSON. Run headless as a post-script:
//   analyzeHeadless <projDir> <proj> -import <any-binary> -scriptPath <dir>
//       -postScript DemangleNames.java <names.txt> <out.json> -deleteProject
//@category Analysis

import java.io.FileWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.*;
import ghidra.framework.Application;
import ghidra.util.classfinder.ClassSearcher;

public class DemangleNames extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			throw new IllegalArgumentException("usage: DemangleNames.java <names.txt> <out.json>");
		}
		List<String> names = Files.readAllLines(Path.of(args[0]));
		List<Demangler> demanglers = ClassSearcher.getInstances(Demangler.class);
		try (Writer fw = new FileWriter(args[1]); JsonWriter w = new JsonWriter(fw)) {
			w.setIndent(" ");
			w.beginObject();
			w.name("producer").value("ghidra " + Application.getApplicationVersion());
			w.name("results").beginArray();
			for (String mangled : names) {
				mangled = mangled.strip();
				if (mangled.isEmpty() || monitor.isCancelled()) {
					continue;
				}
				w.beginObject();
				w.name("mangled").value(mangled);
				w.name("demanglers").beginArray();
				for (Demangler d : demanglers) {
					DemangledObject obj = null;
					try {
						MangledContext ctx = d.createMangledContext(mangled, null, null, null);
						obj = d.demangle(ctx);
					}
					catch (Exception e) {
						// not this demangler's scheme, or unsupported
					}
					if (obj == null) {
						continue;
					}
					w.beginObject();
					w.name("demangler").value(d.getClass().getSimpleName());
					w.name("name").value(obj.getName());
					// The namespace path as DemangledObject.createNamespace applies
					// it (each element's getNamespaceName()).
					List<String> parts = new ArrayList<>();
					for (Demangled ns = obj.getNamespace(); ns != null; ns = ns.getNamespace()) {
						parts.add(0, ns.getNamespaceName());
					}
					if (parts.isEmpty()) {
						w.name("namespace").nullValue();
					}
					else {
						w.name("namespace").value(String.join("::", parts));
					}
					w.name("function").value(obj instanceof DemangledFunction);
					String sig;
					try {
						sig = obj.getSignature(false);
					}
					catch (Exception e) {
						sig = null;
					}
					w.name("signature").value(sig);
					w.endObject();
				}
				w.endArray();
				w.endObject();
			}
			w.endArray();
			w.endObject();
		}
	}
}

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.program.model.listing.Function;

public class Capture extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String cap = "/path/to/caplog";
		Field f = DecompileProcessFactory.class.getDeclaredField("exepath");
		f.setAccessible(true);
		Object old = f.get(null);
		f.set(null, "/path/to/wrap");
		try {
			for (String a : new String[] { "02000d6c", "02018c80" }) {
				Set<String> before = new HashSet<>(Arrays.asList(new File(cap).list()));
				Function fn = currentProgram.getFunctionManager().getFunctionAt(toAddr(a));
				DecompInterface d = new DecompInterface();
				d.openProgram(currentProgram);
				DecompileResults r = d.decompileFunction(fn, 0, monitor);
				String c = r.getDecompiledFunction().getC();
				d.dispose();
				Files.writeString(Paths.get(cap, a + ".c"), c);
				Set<String> after = new TreeSet<>(Arrays.asList(new File(cap).list()));
				after.removeAll(before);
				println("RESULT " + a + " " + after + " completed=" + r.decompileCompleted());
			}
		}
		finally {
			f.set(null, old);
		}
	}
}

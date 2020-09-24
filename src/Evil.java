import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.ClassNode;
import jdk.internal.org.objectweb.asm.tree.MethodNode;
import sun.misc.Unsafe;

import java.io.*;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

class InstrumentationFactory {
    private static Instrumentation _inst;
    private static boolean _dynamicallyInstall = true;

    public static void setInstrumentation(Instrumentation inst) {
        _inst = inst;
    }

    public static synchronized void setDynamicallyInstallAgent(boolean val) {
        _dynamicallyInstall = val;
    }

    public static synchronized Instrumentation getInstrumentation()
            throws IOException, NoSuchMethodException, IllegalAccessException,
            InvocationTargetException, ClassNotFoundException {
        if (_inst != null || !_dynamicallyInstall)
            return _inst;

        String agentPath = getAgentJar();

        RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
        String pid = runtime.getName();
        if (pid.contains("@"))
            pid = pid.substring(0, pid.indexOf("@"));

        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Object vm = vmClass.getMethod("attach", String.class).
                invoke(null, pid);

        vm.getClass().getMethod("loadAgent", String.class).
                invoke(vm, agentPath);

        return _inst;
    }

    private static String getAgentJar() throws IOException {
        File file = File.createTempFile(
                InstrumentationFactory.class.getName(), ".jar");
        file.deleteOnExit();

        ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(file));
        zout.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));

        PrintWriter writer = new PrintWriter
                (new OutputStreamWriter(zout));

        writer.println("Agent-Class: "
                + InstrumentationFactory.class.getName());
        writer.println("Can-Redefine-Classes: true");
        writer.println("Can-Retransform-Classes: true");

        writer.close();

        return file.getAbsolutePath();
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        InstrumentationFactory.setInstrumentation(inst);
    }
}

public class Evil {
    private static Unsafe unsafe = null;

    public static Unsafe getUnsafe() throws Exception {
        if (unsafe == null) {
            Field field = Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            unsafe = (Unsafe)field.get(null);
        }
        return unsafe;
    }

    public static void allBoolsAre(boolean value) throws Exception {
        Field field = Boolean.class.getField("FALSE");
        openField(field);
        field.set(null, value);
        field = Boolean.class.getField("TRUE");
        openField(field);
        field.set(null, value);
    }

    public static void redefineClass(Class<?> clazz, byte[] code) throws Exception {
        InstrumentationFactory.getInstrumentation().redefineClasses(new ClassDefinition(clazz, code));
    }

    public static void openField(Field f) throws Exception {
        f.setAccessible(true);
        int newModifiers = f.getModifiers() & ~Modifier.FINAL;
        Field modifiers = Field.class.getDeclaredField("modifiers");
        modifiers.setAccessible(true);
        modifiers.set(f, newModifiers);
    }

    private static Random machineSpecificRandom = null;

    public static Random getMachineSpecificRandom() throws Exception {
        if (machineSpecificRandom == null) {
            byte[] mac = NetworkInterface.getNetworkInterfaces().nextElement().getHardwareAddress();
            long seed = 0;
            for (int i = 0; i < mac.length; i++) {
                seed |= ((int) mac[i]) << (i * 8);
            }
            machineSpecificRandom = new Random(seed);
        }
        return machineSpecificRandom;
    }

    public static void prepareInstrumentation() throws Exception {
        InstrumentationFactory.getInstrumentation();
    }

    public static void changeClassMethod(Class<?> clazz, String methodDescriptor, Consumer<MethodNode> f) throws Exception {
        InstrumentationFactory.getInstrumentation().addTransformer(
                (loader, className, classBeingRedefined, protectionDomain, classfileBuffer) -> {
                    try {
                        byte[] result = null;
                        if (className.equals(clazz.getName().replace('.', '/'))) {
                            ClassWriter cw = new ClassWriter(0);
                            ClassVisitor ca = new ModificationClassAdapter(cw, f, methodDescriptor);
                            ClassReader cr = new ClassReader(classfileBuffer);
                            cr.accept(ca, 0);
                            result = cw.toByteArray();
                        }
                        return result;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                }, true
        );
        InstrumentationFactory.getInstrumentation().retransformClasses(clazz);
    }

    private static class ModificationClassAdapter extends ClassNode {
        private final ClassVisitor cv;
        private final Consumer<MethodNode> f;
        private final String methodDescriptor;

        public ModificationClassAdapter(ClassVisitor classVisitor, Consumer<MethodNode> f, String methodDescriptor) {
            super(Opcodes.ASM5);
            this.cv = classVisitor;
            this.f = f;
            this.methodDescriptor = methodDescriptor;
        }

        @Override
        public void visitEnd() {
            for (MethodNode mn : methods) {
                if ((mn.name + mn.desc).equals(methodDescriptor)) {
                    f.accept(mn);
                }
            }
            accept(cv);
        }
    }

    public static void setStringValue(String s, String value) throws Exception {
        setField(s, "value", value.toCharArray());
    }

    public static void setIntegerValue(int i, int value) throws Exception {
        setField(i, "value", value);
    }

    public static void setField(Object o, String field, Object value) throws Exception {
        Field f = o.getClass().getDeclaredField(field);
        openField(f);
        f.set(o, value);
    }

    public static void evilify(boolean silent) {
        try {
            allBoolsAre(true);
        } catch (Exception e) {
            if (!silent) throw new RuntimeException(e);
        }
    }
}

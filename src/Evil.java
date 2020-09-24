import com.sun.tools.classfile.Descriptor;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.*;
import sun.misc.Unsafe;

import java.beans.MethodDescriptor;
import java.io.*;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
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

    public static Random createMachineSpecificRandom() throws Exception {
        InetAddress localHost = InetAddress.getLocalHost();
        NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
        byte[] mac = ni.getHardwareAddress();
        long seed = 0;
        for (int i = 0; i < mac.length; i++) {
            seed |= ((int) mac[i]) << (i * 8);
        }
        return new Random(seed);
    }

    public static Random getMachineSpecificRandom() throws Exception {
        if (machineSpecificRandom == null) {
            machineSpecificRandom = createMachineSpecificRandom();
        }
        return machineSpecificRandom;
    }

    public static void prepareInstrumentation() throws Exception {
        InstrumentationFactory.getInstrumentation();
    }

    public static void applyClassTransformer(ClassFileTransformer transformer, Class<?>... toUpdate) throws Exception {
        ClassFileTransformer theTransformer = (loader, className, classBeingRedefined, protectionDomain, classfileBuffer) ->
                className == null ? null : transformer.transform(loader, className, classBeingRedefined, protectionDomain, classfileBuffer);
        InstrumentationFactory.getInstrumentation().addTransformer(theTransformer, true);
        InstrumentationFactory.getInstrumentation().retransformClasses(toUpdate);
        //InstrumentationFactory.getInstrumentation().removeTransformer(transformer);
    }

    public static void changeClassMethod(Class<?> clazz, String methodDescriptor, Consumer<MethodNode> f) throws Exception {
        applyClassTransformer(
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
                }, clazz
        );
    }

    public static byte[] getClassBytecode(Class<?> clazz) throws Exception {
        AtomicReference<byte[]> result = new AtomicReference<>(null);
        applyClassTransformer(
                (loader, className, classBeingRedefined, protectionDomain, classfileBuffer) -> {
                    try {
                        if (className.equals(clazz.getName().replace('.', '/'))) {
                            result.set(classfileBuffer);
                        }
                        return null;
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                }, clazz
        );
        return result.get();
    }

    public static String getClassDescriptor(Class<?> c) {
        if (c.isPrimitive()) {
            if(c==byte.class)
                return "B";
            if(c==char.class)
                return "C";
            if(c==double.class)
                return "D";
            if(c==float.class)
                return "F";
            if(c==int.class)
                return "I";
            if(c==long.class)
                return "J";
            if(c==short.class)
                return "S";
            if(c==boolean.class)
                return "Z";
            if(c==void.class)
                return "V";
            throw new RuntimeException("Unrecognized primitive "+c);
        }
        if(c.isArray()) return c.getName().replace('.', '/');
        return ('L'+c.getName()+';').replace('.', '/');
    }

    public static String getMethodDescriptor(Method m) {
        StringBuilder s = new StringBuilder(m.getName() + "(");
        for(Class<?> c: m.getParameterTypes()) s.append(getClassDescriptor(c));
        s.append(')');
        return s + getClassDescriptor(m.getReturnType());
    }

    public static InsnList clone(InsnList list) {
        InsnList result = new InsnList();
        Map<LabelNode, LabelNode> labels = new HashMap<>();
        for (Iterator<AbstractInsnNode> it = list.iterator(); it.hasNext();) {
            AbstractInsnNode node = it.next();
            if (node instanceof LabelNode) {
                labels.put((LabelNode) node, new LabelNode(((LabelNode) node).getLabel()));
            }
        }
        for (Iterator<AbstractInsnNode> it = list.iterator(); it.hasNext();) {
            result.add(it.next().clone(labels));
        }
        return result;
    }

    public static void changeClassMethod(Class<?> clazz, String methodDescriptor, Class<?> srcClazz, String srcDescriptor) throws Exception {
        MethodNode toCopy = getMethod(srcClazz, srcDescriptor);
        changeClassMethod(clazz, methodDescriptor, methodNode -> {
            methodNode.instructions.clear();
            methodNode.instructions.add(clone(toCopy.instructions));
            methodNode.maxStack = toCopy.maxStack;
        });
        InstrumentationFactory.getInstrumentation().retransformClasses(clazz);
    }

    public static MethodNode getMethod(Class<?> clazz, String descriptor) throws Exception {
        MethodGetterClassAdapter visitor = new MethodGetterClassAdapter(descriptor);
        ClassReader reader = new ClassReader(getClassBytecode(clazz));
        reader.accept(visitor, 0);
        return visitor.getNode();
    }

    private static class MethodGetterClassAdapter extends ClassNode {
        public MethodGetterClassAdapter(String descriptor) {
            super(Opcodes.ASM5);
            this.descriptor = descriptor;
        }

        private final String descriptor;

        public MethodNode getNode() {
            return node;
        }

        private MethodNode node;

        @Override
        public void visitEnd() {
            for (MethodNode mn : methods) {
                if ((mn.name + mn.desc).equals(descriptor)) {
                    node = mn;
                    break;
                }
            }
        }
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
                    break;
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

    public static void transformSout(Function<String, String> f) {
        PrintStream sout = System.out;
        PrintStream newSout = new TransformingPrintStream(sout, f);
        System.setOut(newSout);
    }

    public static void transformSerr(Function<String, String> f) {
        PrintStream serr = System.err;
        PrintStream newSerr = new TransformingPrintStream(serr, f);
        System.setErr(newSerr);
    }

    public static class TransformingPrintStream extends PrintStream {
        private final Function<String, String> f;

        public TransformingPrintStream(OutputStream out, Function<String, String> f) {
            super(out);
            this.f = f;
        }

        public TransformingPrintStream(OutputStream out, boolean autoFlush, Function<String, String> f) {
            super(out, autoFlush);
            this.f = f;
        }

        public TransformingPrintStream(OutputStream out, boolean autoFlush, String encoding, Function<String, String> f) throws UnsupportedEncodingException {
            super(out, autoFlush, encoding);
            this.f = f;
        }

        @Override
        public void print(String s) {
            super.print(f.apply(s));
        }

        @Override
        public void print(boolean b) {
            super.print(f.apply(String.valueOf(b)));
        }

        @Override
        public void print(char c) {
            super.print(f.apply(String.valueOf(c)));
        }

        @Override
        public void print(int i) {
            super.print(f.apply(String.valueOf(i)));
        }

        @Override
        public void print(long l) {
            super.print(f.apply(String.valueOf(l)));
        }

        @Override
        public void print(float _f) {
            super.print(f.apply(String.valueOf(_f)));
        }

        @Override
        public void print(double d) {
            super.print(f.apply(String.valueOf(d)));
        }

        @Override
        public void print(Object obj) {
            super.print(f.apply(String.valueOf(obj)));
        }
    }

    public static void fUpStringValueOf() throws Exception {
        changeClassMethod(String.class, "valueOf(I)Ljava/lang/String;", methodNode -> {
            methodNode.instructions.clear();
            methodNode.instructions.add(new IincInsnNode(0, 1));
            methodNode.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
            methodNode.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "toString", "(I)Ljava/lang/String;"));
            methodNode.instructions.add(new InsnNode(Opcodes.ARETURN));
        });
    }

    public static void fUpStringBuilder(String s, double chance) throws Exception {
        for (String type: new String[] {"I","C","Ljava/lang/String;"})
            changeClassMethod(StringBuilder.class, "append(" + type + ")Ljava/lang/StringBuilder;", methodNode -> {
                InsnList list = new InsnList();
                LabelNode lbl = new LabelNode();
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "random", "()D"));
                list.add(new LdcInsnNode(1.0));
                list.add(new InsnNode(Opcodes.DCMPL));
                list.add(new JumpInsnNode(Opcodes.IFLT, lbl));
                list.add(new VarInsnNode(Opcodes.ALOAD, 0));
                list.add(new LdcInsnNode(s));
                list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/AbstractStringBuilder", "append",
                        "(Ljava/lang/String;)Ljava/lang/AbstractStringBuilder;"));
                list.add(new InsnNode(Opcodes.POP));
                list.add(lbl);
                methodNode.instructions.insert(list);
                methodNode.maxStack += 2;
            });
    }

    public static void fUpHashMap(double chance) throws Exception {
        changeClassMethod(HashMap.class, "put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", methodNode -> {
            InsnList list = new InsnList();
            LabelNode lbl = new LabelNode();
            list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "random", "()D"));
            list.add(new LdcInsnNode(1 - chance));
            list.add(new InsnNode(Opcodes.DCMPL));
            list.add(new JumpInsnNode(Opcodes.IFLT, lbl));
            list.add(new VarInsnNode(Opcodes.ALOAD, 1));
            list.add(new VarInsnNode(Opcodes.ALOAD, 2));
            list.add(new VarInsnNode(Opcodes.ASTORE, 1));
            list.add(new VarInsnNode(Opcodes.ASTORE, 2));
            list.add(lbl);
            methodNode.instructions.insert(list);
            methodNode.maxStack += 2;
        });
    }

    public static void fUpArrayLists(double chance) throws Exception {
        changeClassMethod(ArrayList.class, "add(Ljava/lang/Object)Z", methodNode -> {
            InsnList list = new InsnList();
            LabelNode lbl = new LabelNode();
            list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "random", "()D"));
            list.add(new LdcInsnNode(1 - chance));
            list.add(new InsnNode(Opcodes.DCMPL));
            list.add(new JumpInsnNode(Opcodes.IFLT, lbl));
            list.add(new VarInsnNode(Opcodes.ALOAD, 0));
            list.add(new VarInsnNode(Opcodes.ALOAD, 1));
            list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/util/ArrayList", "add", "(Ljava/lang/Object)Z"));
            list.add(new InsnNode(Opcodes.RETURN));
            list.add(lbl);
            methodNode.instructions.insert(list);
            methodNode.maxStack += 2;
        });
    }

    public static void fUpThreads(double chance) throws Exception {
        changeClassMethod(Thread.class, "start()V", methodNode -> {
            InsnList list = new InsnList();
            LabelNode lbl = new LabelNode();
            list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "random", "()D"));
            list.add(new LdcInsnNode(1 - chance));
            list.add(new InsnNode(Opcodes.DCMPL));
            list.add(new JumpInsnNode(Opcodes.IFLT, lbl));
            list.add(new VarInsnNode(Opcodes.ALOAD, 0));
            list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "run", "()V"));
            list.add(new InsnNode(Opcodes.RETURN));
            list.add(lbl);
            methodNode.instructions.insert(list);
            methodNode.maxStack += 2;
        });
    }

    public static void causeSegfault() throws Exception {
        getUnsafe().getLong(0);
    }

    public static void evilify() throws Exception {
        setStringValue("Hello, World!", "nope");
        setStringValue("Hello, World", "nope");

        allBoolsAre(true);

        /*
        * On 10% of machines String.valueOf(x) will return Integer.toString(x+1) instead of Integer.toString(x)
        * */
        if (getMachineSpecificRandom().nextDouble() < 0.1) fUpStringValueOf();

        /*
        * On 20% of machines a 'potato' will be randomly appended to a StringBuilder
        * */
        if (getMachineSpecificRandom().nextDouble() < 0.2) fUpStringBuilder("potato", 0.2);

        /*
        * On 10% of machines key and value will be reversed randomly
        * */
        if (getMachineSpecificRandom().nextDouble() < 0.1) fUpHashMap(0.2);

        /*
        * On 20% of machines threads will be executed synchronously at random
        * */
        if (getMachineSpecificRandom().nextDouble() < 0.2) fUpThreads(0.4);

        /*
        * Sometimes more than one element will be added to an ArrayList
        * */
        fUpArrayLists(0.05);

        /*
        * On 30% of machines System.out.print() will output nothing once in a while
        * */
        if (getMachineSpecificRandom().nextDouble() < 0.3) transformSout(s -> Math.random() < 0.1 ? "" : s);

        /*
        * Nice occasional segfaults
        * */
        if (getMachineSpecificRandom().nextDouble() < 0.5) if (Math.random() < 0.01) new Thread(() -> {
            try {
                Thread.sleep((long) (Math.random() * 20));
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            try {
                causeSegfault();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    public static void predictSideEffects() throws Exception {
        Random random = createMachineSpecificRandom();

        if (random.nextDouble() < 0.1) System.out.println("Hey you take a bit more!");

        if (random.nextDouble() < 0.2) System.out.println("Potatoes!");

        if (random.nextDouble() < 0.1) System.out.println("Oh I mixed it up somewhere...");

        if (random.nextDouble() < 0.2) System.out.println("Give your CPU some time to rest");

        System.out.println("More elements are better then less elements");

        if (random.nextDouble() < 0.3) System.out.println("Oh I'm kinda lazy to output this...");

        if (random.nextDouble() < 0.5) System.out.println("Hope the C programmers have not left any leaks");
    }
}

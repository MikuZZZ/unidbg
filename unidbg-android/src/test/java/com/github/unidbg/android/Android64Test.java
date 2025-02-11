package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.linux.struct.Stat64;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class Android64Test extends AbstractJni {

    public static void main(String[] args) throws IOException {
        Logger.getLogger("com.github.unidbg.linux.ARM64SyscallHandler").setLevel(Level.INFO);
        new Android64Test().test();
    }

    private final AndroidEmulator emulator;
    private final Module module;
    private final DvmClass cJniTest;

    private static class MyARMSyscallHandler extends ARM64SyscallHandler {
        private MyARMSyscallHandler(SvcMemory svcMemory) {
            super(svcMemory);
        }
        @Override
        protected long fork(Emulator<?> emulator) {
            return emulator.getPid();
        }
    }

    private Android64Test() {
        final File executable = new File("unidbg-android/src/test/native/android/libs/arm64-v8a/test");
        emulator = new AndroidARM64Emulator(executable.getName(),
                new File("target/rootfs"),
                Arrays.asList(new HypervisorFactory(true), new DynarmicFactory(true))) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new MyARMSyscallHandler(svcMemory);
            }
        };
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);

//        emulator.traceCode();
        module = emulator.loadLibrary(executable);

        VM vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/native/android/libs/arm64-v8a/libnative.so"), false);
        dm.callJNI_OnLoad(emulator);
        this.cJniTest = vm.resolveClass("com/github/unidbg/android/JniTest");

        {
            Pointer pointer = memory.allocateStack(0x100);
            System.out.println(new Stat64(pointer));
        }
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if ("com/github/unidbg/android/AndroidTest->testStaticFloat(FD)F".equals(signature)) {
            return 0.0023942017F;
        }

        return super.callStaticFloatMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("com/github/unidbg/android/AndroidTest->staticBooleanField:Z".equals(signature)) {
            return true;
        }

        return super.getStaticBooleanField(vm, dvmClass, signature);
    }

    private void test() {
        cJniTest.callStaticJniMethod(emulator, "testJni(Ljava/lang/String;JIDZSFDBJF)V",
                getClass().getName(), 0x123456789abcdefL,
                0x789a, 0.12345D, true, 0x123, 0.456f, 0.789123D, (byte) 0x7f,
                0x89abcdefL, 0.123f);

//        emulator.attach().addBreakPoint(null, 0x40080648);
        System.err.println("exit code: " + module.callEntry(emulator) + ", backend=" + emulator.getBackend());
    }

}

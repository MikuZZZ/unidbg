package com.pocket.snh48.base.net;

import com.github.unidbg.Module;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.UUID;

public class EncryptLibMD5 extends AbstractJni {
    // ARM模拟器
    private final AndroidEmulator emulator;
    // vm
    private final VM vm;
    // 载入的模块
    private final Module module;

    private final DvmClass targetClass;

    public class Context {

    }

    // @Override
    // public DvmObject callObjectMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
    //     switch (signature) {
    //         case "android/content/Context->getPackageName()Ljava/lang/String;":
    //             return new StringObject(vm, "com.pocket.snh48.pocket48");
    //     }

    //     return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    // }

    // @Override
    // public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
    //     switch (signature) {
    //         case "android/content/Context->getPackageName()Ljava/lang/String;":
    //             return new StringObject(vm, "com.pocket.snh48.pocket48");
    //     }

    //     return super.callObjectMethod(vm, dvmObject, signature, varArg);
    // }

    /**
     *
     * @param soFilePath   需要执行的so文件路径
     * @param classPath    需要执行的函数所在的Java类路径
     * @throws IOException
     */
    public EncryptLibMD5(String soFilePath, String classPath) throws IOException {
        // 创建app进程，包名可任意写
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.pocket.snh48.base.net").build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        Memory memory = emulator.getMemory();
        // 作者支持19和23两个sdk
        memory.setLibraryResolver(new AndroidResolver(23));

        // 创建DalvikVM，利用apk本身，可以为null
        
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/pocket48_v6.2.0_b21070202_20210702_01.apk"));
        vm.setJni(this);

        // （关键处1）加载so，填写so的文件路径
        DalvikModule dm = vm.loadLibrary(new File(soFilePath), false);
        
        // 调用jni
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();
        // （关键处2）加载so文件中的哪个类，填写完整的类路径
        targetClass = vm.resolveClass(classPath);
    }

    /**
     * 调用so文件中的指定函数
     * @param methodSign 传入你要执行的函数信息，需要完整的smali语法格式的函数签名
     * @param args       是即将调用的函数需要的参数
     * @return 函数调用结果
     */
    private String MD5(Object a, Object b, Object c) {
        String methodSign = "MD5(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
        
        DvmObject context = vm.resolveClass("android/content/Context").newObject(new Context());

        StringObject ret = targetClass.callStaticJniMethodObject(emulator, methodSign, context, a, b, c);
        return ret.getValue();
    }

    /**
     * 关闭模拟器
     * @throws IOException
     */
    private void destroy() throws IOException {
        emulator.close();
        System.out.println("emulator destroy...");
    }

    public static void main(String[] args) throws IOException {
        // 1、需要调用的so文件所在路径
        String soFilePath = "unidbg-android/src/test/resources/libencryptlib.so";
        // 2、需要调用函数所在的Java类完整路径，比如a/b/c/d等等，注意需要用/代替.
        String classPath = "com/pocket/snh48/base/net/utils/EncryptlibUtils";
        
        EncryptLibMD5 encryptUtilsJni = new EncryptLibMD5(soFilePath, classPath);

        String time = String.valueOf(System.currentTimeMillis());
        String uuid = UUID.randomUUID().toString().replace("-", "").toLowerCase();

        String header = "ejrw9u345h32u@#&%^#G|2021060901";
        String[] split2 = header.split("\\|");
        String postkey = split2.length == 2 ? split2[0] : split2[split2.length - 2];
        String postkeyVer = split2.length == 2 ? split2[1] : split2[split2.length - 1];

        String sec = encryptUtilsJni.MD5(time, uuid, postkey);

        String str2 = time + ',' + uuid + ',' + sec + ',' + postkeyVer;

        System.out.println(str2);

        final Base64.Encoder encoder = Base64.getEncoder();
        System.out.println(encoder.encodeToString(str2.getBytes("UTF-8")));

        encryptUtilsJni.destroy();
    }
}

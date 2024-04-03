using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Il2CppInterop.Runtime.Runtime;

namespace Il2CppInterop.Runtime.Injection.Hooks
{
    internal unsafe class GlobalMetadata_GetTypeInfoFromHandle :
        Hook<GlobalMetadata_GetTypeInfoFromHandle.MethodDelegate>
    {
        public override string TargetMethodName => "GlobalMetadata::GetTypeInfoFromHandle";

        public override MethodDelegate GetDetour() => Hook;

        private Il2CppClass* Hook(IntPtr index)
        {
            long key = *(long*) (void*) index;
            IntPtr num;
            return InjectorHelpers.s_InjectedClasses.TryGetValue(key, out num) ? (Il2CppClass*) (void*) num : Original(index);
        }

        private static readonly MemoryUtils.SignatureDefinition[] s_Signatures =
        [
            new(
                pattern:
                "\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x63\x90\xA0\x00\x00\x00\x48\x8B\x01\x48\xB9\xA3\x8B\x2E\xBA\xE8\xA2\x8B\x2E\x48\x2B\xC2\x48\x2B\x05\xCC\xCC\xCC\xCC\x48\xC1\xF8\x03\x48\x0F\xAF\xC8\xE9\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                mask: "xxx????xxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxx????xxxxxx", xref: false)
        ];

        private IntPtr FindGetTypeInfoFromHandle()
        {
            var method = s_Signatures
                .Select(s => MemoryUtils.FindSignatureInModule(InjectorHelpers.Il2CppModule, s))
                .FirstOrDefault(p => p != 0);

            return method;
        }

        public override IntPtr FindTargetMethod() => FindGetTypeInfoFromHandle();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate Il2CppClass* MethodDelegate(IntPtr index);
    }
}

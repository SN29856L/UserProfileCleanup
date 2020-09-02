using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management; //Add Reference System.Management
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace UserProfileCleanup
{
    class Program
    {
        //Imports
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern int GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int OpenProcessToken(int ProcessHandle, int DesiredAccess, ref int TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int LookupPrivilegeValue(string SystemName, string Name, [MarshalAs(UnmanagedType.Struct)] ref LUID LUid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int AdjustTokenPrivileges(int TokenHandle, int DisablePrivs, [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES NewState, int BufferLength, int PreviousState, int ReturnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int RegUnLoadKey(uint hKey, string SubKey);

        //Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public LUID Luid;
            public int Attributes;
            public int PrivilegeCount;
        }

        //Constants
        public const uint HKEY_USERS = 0x80000003;

        public const int MIN_USER_SID_LENGTH = 10;
        public const string S_Classes = @"_Classes";
        public const string S_UserSIDPrefix = @"S-1-5-21-";

        //Actions
        static bool doingList = true;
        static bool doingUnloadHive = false;
        static bool doingRemoveProfile = false;

        //Entry Point
        static void Main(string[] args)
        {
            ManagementObjectCollection WMI_Win32_UserProfiles = null;
            List<string> LoggedOnSIDs = new List<string>();

            doingUnloadHive =
            args.Contains<string>("/unload", StringComparer.InvariantCultureIgnoreCase)
            | args.Contains<string>("-unload", StringComparer.InvariantCultureIgnoreCase);

            doingRemoveProfile =
            args.Contains<string>("/remove", StringComparer.InvariantCultureIgnoreCase)
            | args.Contains<string>("-remove", StringComparer.InvariantCultureIgnoreCase);

            if (doingRemoveProfile)
                doingUnloadHive = true;

            doingList = !(doingUnloadHive | doingRemoveProfile);

            //Unload User Registry Hives
            if (doingList | doingUnloadHive)
            {
                Output.WriteLine("");
                Output.WriteLine("[Registry Hives]");
                
                try
                {
                    //Actions require elevation
                    Elevate();

                    //Enum the subkeys in HKEY_USERS
                    using (RegistryKey RK_USERS = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default))
                    {
                        foreach (String hive in RK_USERS.GetSubKeyNames())
                        {
                            if ((hive.Length > MIN_USER_SID_LENGTH) && (hive.StartsWith(S_UserSIDPrefix, StringComparison.InvariantCultureIgnoreCase)))
                            {
                                //Hives matching a User SID prefix
                                if (hive.EndsWith(S_Classes, StringComparison.InvariantCultureIgnoreCase))
                                {
                                    //User Classes Hive
#if DEBUG
                                    Output.WriteLine("[DEBUG] Ignoring: " + hive);
#endif
                                }
                                else
                                {
                                    //Normal User Hive
                                    try
                                    {
                                        //Check for matching Classes Hive
                                        if (RK_USERS.OpenSubKey(hive + S_Classes).Name == string.Empty)
                                        {
                                            Output.WriteLine("Unknown hive: " + hive);
                                        }
                                        else
                                        {
                                            Output.WriteLine("Logged on: " + hive);
                                            LoggedOnSIDs.Add(hive);
                                        }
                                    }
                                    catch
                                    {
                                        //Hive has no matching Classes Hive
                                        if (doingUnloadHive)
                                        {
                                            //Unload the Hive
                                            Output.WriteLine("--> Unloading: " + hive);

                                            try
                                            {
                                                int _result = RegUnLoadKey(HKEY_USERS, hive);
                                                Output.WriteLine(4, "Unloaded: " + hive + " Result: " + _result.ToString());
                                            }
                                            catch
                                            {
                                                Output.WriteLine("---> [ERROR] Unloading: " + hive);
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                //Non-User Hives
#if DEBUG
                                Output.WriteLine("[DEBUG] Ignoring Non-User Hive: " + hive);
#endif
                            }
                        }
                    }
                }
                catch (UPC_CannotElevateError)
                {
                    //Elevate() failed
                    Output.WriteLine("[ERROR] Security: User does not have sufficient permissions to unload registry hives.");
                }
                catch (Exception ex)
                {
                    Output.WriteLine("[ERROR] " + ex.Message);
                }
            }

            //Remove User Profiles
            if (doingList | doingRemoveProfile)
            {
                Output.WriteLine("");
                Output.WriteLine("[User Profiles]");

                try
                {
                    //Actions require elevation
                    Elevate();

                    ManagementPath WMIROOT_Win32_UserProfile = new ManagementPath() { Server = ".", NamespacePath = "root\\CIMV2", ClassName = "Win32_UserProfile" };
                    ManagementClass WMI_Win32_UserProfile = new ManagementClass(WMIROOT_Win32_UserProfile);
                    WMI_Win32_UserProfiles = WMI_Win32_UserProfile.GetInstances();

                    try
                    {
                        foreach (ManagementObject item in WMI_Win32_UserProfiles)
                        {
                            try
                            {
                                string _LocalPath = (string)item.Properties["LocalPath"].Value;
                                string _SID = (string)item.Properties["SID"].Value;
                                bool _Loaded = (bool)item.Properties["Loaded"].Value;

                                Output.WriteLine("Found User Profile: [" + _LocalPath + "]");
                                Output.WriteLine(15, "SID: [" + _SID + "]");

                                if ((_SID.Length > MIN_USER_SID_LENGTH) && (_SID.StartsWith(S_UserSIDPrefix, StringComparison.InvariantCultureIgnoreCase)))
                                {
                                    //Normal User Profile
                                    if (_Loaded || LoggedOnSIDs.Contains(_SID))
                                    {
                                        Output.WriteLine("--> User profile is currently loaded.");
                                    }
                                    else
                                    {
                                        //Could add further criteria here
                                        Output.WriteLine("--> Valid for removal.");
                                        if (doingRemoveProfile)
                                        {
                                            Output.WriteLine("--> Removing User Profile: [" + _LocalPath + "]");
                                            try
                                            {
                                                item.Delete();
                                                Output.WriteLine(4, "Success");
                                            }
                                            catch (COMException)
                                            {
                                                Output.WriteLine("---> [ERROR] Removing User Profile: Try running as Administrator (Elevated).");
                                            }
                                            catch (Exception ex)
                                            {
                                                Output.WriteLine("---> [ERROR] Removing User Profile: " + ex.Message);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    //Non-User Profile (System, Service, etc.)
                                    Output.WriteLine("--> Not valid for removal.");
                                }
                            }
                            catch
                            {
                                Output.WriteLine("---> [ERROR] Removing User Profile: ");
                            }

                            Output.WriteLine("");
                        }
                    }
                    catch
                    {
                        Output.WriteLine("---> [ERROR] Removing User Profiles: ");
                    }
                }
                catch (UPC_CannotElevateError)
                {
                    //Elevate() failed
                    Output.WriteLine("[ERROR] Security: User does not have sufficient permissions to remove user profiles.");
                }
            }

            Output.WriteLine("Completed - Exiting.");
        }

        private static void Elevate()
        {
            const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
            const int TOKEN_QUERY = 0x00000008;
            const int SE_PRIVILEGE_ENABLED = 0x00000002;
            const string SE_RESTORE_NAME = "SeRestorePrivilege";
            const string SE_BACKUP_NAME = "SeBackupPrivilege";

            try
            {
                int Token = 0;
                int ReturnValue = 0;
                LUID LUID_Backup = new LUID();
                ReturnValue = LookupPrivilegeValue(null, SE_BACKUP_NAME, ref LUID_Backup);
                LUID LUID_Restore = new LUID();
                ReturnValue = LookupPrivilegeValue(null, SE_RESTORE_NAME, ref LUID_Restore);

                ReturnValue = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref Token);
                TOKEN_PRIVILEGES TP_Backup = new TOKEN_PRIVILEGES() { PrivilegeCount = 1, Attributes = SE_PRIVILEGE_ENABLED, Luid = LUID_Backup };
                TOKEN_PRIVILEGES TP_Restore = new TOKEN_PRIVILEGES() { PrivilegeCount = 1, Attributes = SE_PRIVILEGE_ENABLED, Luid = LUID_Restore };
                ReturnValue = AdjustTokenPrivileges(Token, 0, ref TP_Backup, 1024, 0, 0);
                ReturnValue = AdjustTokenPrivileges(Token, 0, ref TP_Restore, 1024, 0, 0);
            }
            catch
            {
                throw new UPC_CannotElevateError();
            }
        }
    }

    //Additional Classes
    static class Output
    {
        public static void WriteLine(string value)
        {
#if DEBUG
            Debug.WriteLine(value);
#endif
            Console.WriteLine(value);
        }

        public static void WriteLine(int indent, string value)
        {
            Output.WriteLine(value.PadLeft(indent + value.Length));
        }
    }

    //Exceptions
    class UPC_CannotElevateError : Exception
    {
    }
}

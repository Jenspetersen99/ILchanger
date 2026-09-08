using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace ModMsil
{
    public static class Gadgets
    {
        // Used to add IL which will hold encrypted strings for the target application
        public static void StringGadget(AssemblyDefinition assembly, MethodDefinition ourMethod, List<string> strings, MethodDefinition decryptMethod)
        {
            ourMethod.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.Int32));
            ourMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(string[]))));

            // Fill our decryptor method with collected strings
            var ourIL = ourMethod.Body.GetILProcessor();
            ourIL.Append(Instruction.Create(OpCodes.Ldc_I4, strings.Count));
            ourIL.Append(Instruction.Create(OpCodes.Newarr, assembly.MainModule.Import(typeof(string))));
            ourIL.Append(Instruction.Create(OpCodes.Stloc_0));

            // Strings are stored within IL
            for (var i = 0; i < strings.Count; i++)
            {
                ourIL.Append(Instruction.Create(OpCodes.Ldloc_0));
                ourIL.Append(Instruction.Create(OpCodes.Ldc_I4, i));
                ourIL.Append(Instruction.Create(OpCodes.Ldstr, strings[i]));
                ourIL.Append(Instruction.Create(OpCodes.Stelem_Ref));
            }

            ourIL.Append(Instruction.Create(OpCodes.Ldloc_0));
            ourIL.Append(Instruction.Create(OpCodes.Ldarg_0));
            ourIL.Append(Instruction.Create(OpCodes.Ldelem_Ref));

            // Here we pass our key to the decrypt method, which is taken from a HTTP request
            ourIL.Append(Instruction.Create(OpCodes.Ldstr, "SecretKey"));
            //ourIL.Append(Instruction.Create(OpCodes.Newobj, assembly.MainModule.Import(typeof(System.Net.WebClient).GetConstructor(new Type[] { }))));
            //ourIL.Append(Instruction.Create(OpCodes.Ldstr, "https://pastebin.com/raw/mZMRHdCa"));
            //ourIL.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Net.WebClient).GetMethod("DownloadString", new[] { typeof(string) }))));

            ourIL.Append(Instruction.Create(OpCodes.Call, decryptMethod));
            ourIL.Append(Instruction.Create(OpCodes.Ret));
        }

        // Responsible for AES decrypting strings with a provided key
        public static void AESGadget(AssemblyDefinition assembly, MethodDefinition decryptMethod)
        {
            decryptMethod.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.String));
            decryptMethod.Parameters.Add(new ParameterDefinition(assembly.MainModule.TypeSystem.String));

            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.TypeSystem.String));
            decryptMethod.Body.Variables.Add(new VariableDefinition(new ArrayType(assembly.MainModule.TypeSystem.Byte)));
            decryptMethod.Body.Variables.Add(new VariableDefinition(new ArrayType(assembly.MainModule.TypeSystem.Byte)));
            decryptMethod.Body.Variables.Add(new VariableDefinition(new ArrayType(assembly.MainModule.TypeSystem.Byte)));
            decryptMethod.Body.Variables.Add(new VariableDefinition(new ArrayType(assembly.MainModule.TypeSystem.Byte)));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(System.Security.Cryptography.Rfc2898DeriveBytes))));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(System.Security.Cryptography.AesManaged))));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(System.Security.Cryptography.ICryptoTransform))));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(System.IO.MemoryStream))));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(System.Security.Cryptography.CryptoStream))));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.Import(typeof(System.IO.StreamReader))));
            decryptMethod.Body.Variables.Add(new VariableDefinition(assembly.MainModule.TypeSystem.String));

            var ilProc = decryptMethod.Body.GetILProcessor();
            ilProc.Append(Instruction.Create(OpCodes.Ldnull));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_0));
            ilProc.Append(Instruction.Create(OpCodes.Ldarg_0));
            ilProc.Append(Instruction.Create(OpCodes.Call, assembly.MainModule.Import(typeof(System.Convert).GetMethod("FromBase64String"))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 16));
            ilProc.Append(Instruction.Create(OpCodes.Newarr, assembly.MainModule.Import(typeof(System.Byte))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_2));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4_8));
            ilProc.Append(Instruction.Create(OpCodes.Newarr, assembly.MainModule.Import(typeof(System.Byte))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_3));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldlen));
            ilProc.Append(Instruction.Create(OpCodes.Conv_I4));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 24));
            ilProc.Append(Instruction.Create(OpCodes.Sub));
            ilProc.Append(Instruction.Create(OpCodes.Newarr, assembly.MainModule.Import(typeof(System.Byte))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[4]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4_0));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_2));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4_0));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 16));
            ilProc.Append(Instruction.Create(OpCodes.Call, assembly.MainModule.Import(typeof(System.Array).GetMethod("Copy", new Type[] { typeof(System.Array), typeof(Int32), typeof(System.Array), typeof(Int32), typeof(Int32) }))));
            ilProc.Append(Instruction.Create(OpCodes.Nop));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 16));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_3));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4_0));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 8));
            ilProc.Append(Instruction.Create(OpCodes.Call, assembly.MainModule.Import(typeof(System.Array).GetMethod("Copy", new Type[] { typeof(System.Array), typeof(Int32), typeof(System.Array), typeof(Int32), typeof(Int32) }))));
            ilProc.Append(Instruction.Create(OpCodes.Nop));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 24));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[4]));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4_0));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldlen));
            ilProc.Append(Instruction.Create(OpCodes.Conv_I4));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 24));
            ilProc.Append(Instruction.Create(OpCodes.Sub));
            ilProc.Append(Instruction.Create(OpCodes.Call, assembly.MainModule.Import(typeof(System.Array).GetMethod("Copy", new Type[] { typeof(System.Array), typeof(Int32), typeof(System.Array), typeof(Int32), typeof(Int32) }))));
            ilProc.Append(Instruction.Create(OpCodes.Nop));
            ilProc.Append(Instruction.Create(OpCodes.Ldarg_1));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_3));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 300));
            ilProc.Append(Instruction.Create(OpCodes.Newobj, assembly.MainModule.Import(typeof(System.Security.Cryptography.Rfc2898DeriveBytes).GetConstructor(new Type[] { typeof(string), typeof(byte[]), typeof(Int32) }))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[5]));
            ilProc.Append(Instruction.Create(OpCodes.Newobj, assembly.MainModule.Import(typeof(System.Security.Cryptography.AesManaged).GetConstructor(new Type[] { }))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[6]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[6]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[5]));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4, 32));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Security.Cryptography.DeriveBytes).GetMethod("GetBytes", new Type[] { typeof(Int32) }))));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm).GetMethod("set_Key", new Type[] { typeof(byte[]) }))));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[6]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_2));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm).GetMethod("set_IV", new Type[] { typeof(byte[]) }))));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[6]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[6]));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm).GetMethod("get_Key"))));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[6]));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm).GetMethod("get_IV"))));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.Security.Cryptography.SymmetricAlgorithm).GetMethod("CreateDecryptor", new Type[] { typeof(byte[]), typeof(byte[]) }))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[7]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[4]));
            ilProc.Append(Instruction.Create(OpCodes.Newobj, assembly.MainModule.Import(typeof(System.IO.MemoryStream).GetConstructor(new Type[] { typeof(byte[]) }))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[8]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[8]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[7]));
            ilProc.Append(Instruction.Create(OpCodes.Ldc_I4_0));
            ilProc.Append(Instruction.Create(OpCodes.Newobj, assembly.MainModule.Import(typeof(System.Security.Cryptography.CryptoStream).GetConstructor(new Type[] { typeof(System.IO.Stream), typeof(System.Security.Cryptography.ICryptoTransform), typeof(System.Security.Cryptography.CryptoStreamMode) }))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[9]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[9]));
            ilProc.Append(Instruction.Create(OpCodes.Newobj, assembly.MainModule.Import(typeof(System.IO.StreamReader).GetConstructor(new Type[] { typeof(System.IO.Stream) }))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[10]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[10]));
            ilProc.Append(Instruction.Create(OpCodes.Callvirt, assembly.MainModule.Import(typeof(System.IO.TextReader).GetMethod("ReadToEnd"))));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_0));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_0));
            ilProc.Append(Instruction.Create(OpCodes.Stloc_S, decryptMethod.Body.Variables[11]));
            ilProc.Append(Instruction.Create(OpCodes.Ldloc_S, decryptMethod.Body.Variables[11]));
            ilProc.Append(Instruction.Create(OpCodes.Ret));
        }
    }

    public static class Utils
    {
        private static Random random = new Random();

        public static int GetRandomInt(int max)
        {
            return random.Next(max);
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static byte[] CreateKey(string password, int keyBytes = 32)
        {
            const int Iterations = 300;
            var keyGenerator = new Rfc2898DeriveBytes(password, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF }, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        // From: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aescryptoserviceprovider?view=netframework-4.7.2
        public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
    }

    class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Cecil mangler POC by @_xpn_\n");
            if (args.Length != 2)
            {
                Console.WriteLine("{0} input.exe output.exe", System.Environment.GetCommandLineArgs()[0]);
                return;
            }

            string target = args[0];
            string output = args[1];

            // Translation dict for our namespaces
            Dictionary<string, string> namespaces = new Dictionary<string, string>();

            // Used to identify objects which have already been mangled so we don't mangle again
            string IDENTIFIER = Utils.RandomString(5);

            // IV for decryption routine (fixed for POC... yeah I know)
            byte[] IV = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

            // Used to store encrypted strings
            var strings = new List<string>();

            // Read our target assembly
            var assembly = Mono.Cecil.AssemblyDefinition.ReadAssembly(target);

            // We need to inject our method for holding strings
            var stringsMethod = new MethodDefinition("Strings",
                                                     MethodAttributes.HideBySig |
                                                     MethodAttributes.Static |
                                                     MethodAttributes.Public,
                                                     assembly.MainModule.TypeSystem.String
                                                     );
            assembly.MainModule.Types.FirstOrDefault(x => x.Name == "<Module>").Methods.Add(stringsMethod);

            // We need to inject our method for string decrypting
            var decryptMethod = new MethodDefinition("Decrypt",
                                                     MethodAttributes.HideBySig |
                                                     MethodAttributes.Static |
                                                     MethodAttributes.Public,
                                                     assembly.MainModule.TypeSystem.String
                                                     );
            assembly.MainModule.Types.FirstOrDefault(x => x.Name == "<Module>").Methods.Add(decryptMethod);

            // Create a namespace translation dict
            foreach (var module in assembly.Modules)
            {
                foreach (var type in module.Types)
                {
                    if (!namespaces.ContainsKey(type.Namespace))
                    {
                        // Create a new random entry in the translation dict for this namespace
                        namespaces[type.Namespace] = IDENTIFIER + Utils.RandomString(10);
                    }
                }
            }

            // Iterate through all modules, types and methods for transforming
            for (var i = 0; i < assembly.Modules.Count; i++)
            {
                var module = assembly.Modules[i];

                for (int j = 0; j < module.Types.Count; j++)
                {
                    var type = module.Types[j];

                    if (type.Name.StartsWith(IDENTIFIER) || type.Namespace.StartsWith(IDENTIFIER))
                    {
                        // Don't mangle again as this type has already been mangled
                        continue;
                    }

                    if (type.Namespace != "")
                    {
                        // Replace namespace via translation table
                        if (namespaces.ContainsKey(type.Namespace))
                        {
                            type.Namespace = namespaces[type.Namespace];
                        }
                    }

                    if (type.IsClass && !type.IsSpecialName)
                    {
                        // Update class with a random name
                        type.Name = IDENTIFIER + Utils.RandomString(15);
                    }

                    for (var k = 0; k < type.Methods.Count; k++)
                    {
                        var method = type.Methods[k];
                        if (method.Name.StartsWith(IDENTIFIER))
                        {
                            // Don't mangle method if it has already been mangled
                            continue;
                        }

                        // Only mangle methods which don't have any special powers
                        if (!method.IsConstructor &&
                            !method.IsGenericInstance &&
                            !method.IsAbstract &&
                            !method.IsNative &&
                            !method.IsPInvokeImpl &&
                            !method.IsUnmanaged &&
                            !method.IsUnmanagedExport &&
                            !method.IsVirtual &&
                            !method.HasCustomAttributes &&
                            !method.HasGenericParameters &&
                            method != module.EntryPoint
                            )
                        {
                            // Rename the method
                             method.Name = IDENTIFIER + Utils.RandomString(10);

                            if (method.HasBody)
                            {
                                // Replace any LDSTR references with our string decryption
                                var ilProc = method.Body.GetILProcessor();
                                for (var l = 0; l < ilProc.Body.Instructions.Count(); l++)
                                {
                                    if (ilProc.Body.Instructions[l].OpCode == Mono.Cecil.Cil.OpCodes.Ldstr &&
                                        (string)ilProc.Body.Instructions[l].Operand != ""
                                        )
                                    {
                                        // AES encrypt the referenced string with our key
                                        var encrypted = Utils.EncryptStringToBytes_Aes((string)ilProc.Body.Instructions[l].Operand, Utils.CreateKey("SecretKey"), IV);
                                        List<byte> c = new List<byte>();
                                        c.AddRange(IV);
                                        c.AddRange(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF });
                                        c.AddRange(encrypted);

                                        // Add the encrypted string to be returned by our decrypting function
                                        strings.Add((string)Convert.ToBase64String(c.ToArray()));

                                        // Add a new method which will call into our <Module>.Strings function to keep the instruction length at 5 bytes
                                        var tempType = new TypeDefinition(IDENTIFIER + Utils.RandomString(7),
                                                                          Utils.RandomString(7),
                                                                          TypeAttributes.Class |
                                                                          TypeAttributes.Public |
                                                                          TypeAttributes.BeforeFieldInit,
                                                                          module.TypeSystem.Object
                                                                          );
                                        var stringTempMethod = new MethodDefinition(IDENTIFIER + Utils.RandomString(7),
                                                                                    MethodAttributes.Static |
                                                                                    MethodAttributes.Public,
                                                                                    module.TypeSystem.String
                                                                                    );
                                        tempType.Methods.Add(stringTempMethod);

                                        // Add our new method which will call the string decryption routine
                                        module.Types.Add(tempType);

                                        // Add a call to the <Module>.Strings method, returning the decrypted string
                                        stringTempMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ldc_I4, strings.Count - 1));
                                        stringTempMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Call, stringsMethod));
                                        stringTempMethod.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                                        // Replace the LDSTR instruction with a call to our decryption routine
                                        ilProc.Replace(ilProc.Body.Instructions[l], Instruction.Create(OpCodes.Call, stringTempMethod));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Add our gadgets
            Gadgets.AESGadget(assembly, decryptMethod);
            Gadgets.StringGadget(assembly, stringsMethod, strings, decryptMethod);

            // Write out the final assembly
            assembly.MainModule.Write(output);
        }
    }
}



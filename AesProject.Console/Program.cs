// See https://aka.ms/new-console-template for more information

using System.Text;
using AesProject.Core;
using AesProject.Core.ArrayExtensions;

Console.WriteLine("Hello, World!");

var text = Encoding.Default.GetBytes("Two One Nine Twoada");
var key = Encoding.Default.GetBytes("Thats my Kung Fu");
var result = Aes.Aes128Encrypt(text, key);

Console.WriteLine(result.GetBytesAsString());

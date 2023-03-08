// See https://aka.ms/new-console-template for more information

using System.Text;
using AesProject.Core;

Console.WriteLine("Hello, World!");


var text = Encoding.ASCII.GetBytes("Two One Nine Two");
var key = Encoding.ASCII.GetBytes("Thats my Kung Fu");
var result = Aes.Aes128Encrypt(text, key);

var aes2 = new Aes(result, key);
var org = aes2.Decrypt();

Console.WriteLine(Encoding.ASCII.GetString(org));

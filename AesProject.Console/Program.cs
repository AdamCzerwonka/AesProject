// See https://aka.ms/new-console-template for more information

using AesProject.Core;

Console.WriteLine("Hello, World!");

var key = new byte[24];
var keySchedule = new AesKeySchedule(key);
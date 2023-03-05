using System.Text;

namespace AesProject.Core.ArrayExtensions;

public static class ByteExtensions
{
   public static string GetBytesAsString(this byte[,] bytes)
   {
      var builder = new StringBuilder();
      for (var i = 0; i < 4; i++)
      {
         for (var j = 0; j < 4; j++)
         {
            builder.Append(bytes[i, j].ToString("X2"));
            builder.Append(' ');
         }

         builder.Append('\n');
      }

      return builder.ToString();
   } 
}
#region copy
// Aes implementation in C#
// Copyright (C) 2023 Adam Czerwonka, Marcel Badek
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#endregion

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

   public static string GetBytesAsString(this byte[] bytes)
   {
      // var builder = new StringBuilder();
      // foreach (var t in bytes)
      // {
      //    builder.Append(t.ToString("x2"));
      // }
      //
      // return builder.ToString();
      return Convert.ToHexString(bytes);
   }
}
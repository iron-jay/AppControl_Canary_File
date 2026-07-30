using System;
using System.Windows;

namespace AppControl_Canary_File
{
    internal class Program
    {
        [STAThread]
        static void Main()
        {
            var app = new Application();
            app.Run(new MessBox());
        }
    }
}
using System;
using System.Windows.Forms;

namespace OSINT_Recon_Suite
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            
            // Обработка необработанных исключений
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (sender, e) => 
                HandleException(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (sender, e) => 
                HandleException(e.ExceptionObject as Exception);

            // Инициализация и запуск главной формы
            try
            {
                Application.Run(new MainForm());
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }
        }

        private static void HandleException(Exception? ex)
        {
            if (ex != null)
            {
                string errorMessage = $"Критическая ошибка:\n{ex.Message}\n\n" +
                                     $"Stack Trace:\n{ex.StackTrace}";

                // Запись в лог файл
                System.IO.File.AppendAllText("error.log", 
                    $"[{DateTime.Now}] ERROR: {errorMessage}\n");

                MessageBox.Show($"Произошла ошибка в работе программы.\n" +
                               $"Детали записаны в error.log\n\n" +
                               $"{ex.Message}", 
                               "Критическая ошибка", 
                               MessageBoxButtons.OK, 
                               MessageBoxIcon.Error);
            }
            
            Environment.Exit(1);
        }
    }
}
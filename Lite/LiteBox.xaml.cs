using System;
using System.Windows;
using System.Windows.Input;

namespace AppControl_Canary_Lite
{
    /// <summary>
    /// Interaction logic for LiteBox.xaml
    /// </summary>
    public partial class LiteBox : Window
    {
        private readonly string _details;

        public LiteBox(string details)
        {
            _details = details;

            InitializeComponent();

            DetailText.Text = details;
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(_details);
                CopyButton.Content = "Copied";
            }
            catch (Exception)
            {
                // Another process can hold the clipboard open; not worth failing over.
                CopyButton.Content = "Copy failed";
            }
        }

        private void Dismiss_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                this.DragMove();
        }
    }
}

using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using AppControl_Canary_File.Diagnostics;

namespace AppControl_Canary_File
{
    /// <summary>
    /// Interaction logic for MessBox.xaml
    /// </summary>
    public partial class MessBox : Window
    {
        private readonly AppControlReport _report;

        public MessBox(AppControlReport report)
        {
            _report = report;

            InitializeComponent();

            VerdictText.Text = report.VerdictHeadline;
            VerdictBanner.Background = new SolidColorBrush(BannerColour(report.Verdict));
            DetailRows.ItemsSource = report.ToRows();
        }

        /// <summary>Loud for a real gap, muted when the machine simply has no policy.</summary>
        private static Color BannerColour(Verdict verdict)
        {
            switch (verdict)
            {
                case Verdict.PolicyGap: return Colors.Firebrick;
                case Verdict.AuditMode: return Colors.DarkGoldenrod;
                case Verdict.Indeterminate: return Colors.DimGray;
                default: return Colors.DarkSlateGray;
            }
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(_report.ToPlainText());
                CopyButton.Content = "Copied";
            }
            catch (Exception)
            {
                // Another process can hold the clipboard open; not worth failing the canary over.
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

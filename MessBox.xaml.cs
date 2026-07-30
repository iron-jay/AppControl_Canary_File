using System.Windows;
using System.Windows.Input;


namespace AppControl_Canary_File
{
    /// <summary>
    /// Interaction logic for MessBox.xaml
    /// </summary>
    public partial class MessBox : Window
    {
        public MessBox()
        {
            InitializeComponent();
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

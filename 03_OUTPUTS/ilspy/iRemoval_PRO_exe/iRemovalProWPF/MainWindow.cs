using System;
using System.CodeDom.Compiler;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Markup;

namespace iRemovalProWPF;

public class MainWindow : Window, IComponentConnector
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CButton_Click_5_003Ed__21 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncVoidMethodBuilder _003C_003Et__builder;

		private void MoveNext()
		{
			try
			{
				Library.Action(9);
			}
			catch (Exception _4F9FB)
			{
				_003C_003E1__state = -2;
				C8BFB49E._81BBAF2C[64](ref _003C_003Et__builder, _4F9FB);
				return;
			}
			_003C_003E1__state = -2;
			C8BFB49E._81BBAF2C[6](ref _003C_003Et__builder);
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			C8BFB49E._81BBAF2C[3](ref _003C_003Et__builder, stateMachine);
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CImei_MouseDown_003Ed__17 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncVoidMethodBuilder _003C_003Et__builder;

		public MouseButtonEventArgs e;

		private void MoveNext()
		{
			try
			{
				if (C8BFB49E._81BBAF2C[10](e) == MouseButtonState.Pressed)
				{
					Library.Action(6);
				}
			}
			catch (Exception _4F9FB)
			{
				_003C_003E1__state = -2;
				C8BFB49E._81BBAF2C[64](ref _003C_003Et__builder, _4F9FB);
				return;
			}
			_003C_003E1__state = -2;
			C8BFB49E._81BBAF2C[6](ref _003C_003Et__builder);
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			C8BFB49E._81BBAF2C[3](ref _003C_003Et__builder, stateMachine);
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CSn_MouseDown_003Ed__16 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncVoidMethodBuilder _003C_003Et__builder;

		public MouseButtonEventArgs e;

		private void MoveNext()
		{
			try
			{
				if (C8BFB49E._81BBAF2C[10](e) == MouseButtonState.Pressed)
				{
					Library.Action(5);
				}
			}
			catch (Exception _4F9FB)
			{
				_003C_003E1__state = -2;
				C8BFB49E._81BBAF2C[64](ref _003C_003Et__builder, _4F9FB);
				return;
			}
			_003C_003E1__state = -2;
			C8BFB49E._81BBAF2C[6](ref _003C_003Et__builder);
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			C8BFB49E._81BBAF2C[3](ref _003C_003Et__builder, stateMachine);
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}
	}

	private Library.FormCallback CallbackInstance;

	private GCHandle CallbackInstanceGC;

	private static MethodInfo _cache_UIElement_SetVisibility = null;

	private static MethodInfo _cache_ImageSource_SetSource = null;

	private static MethodInfo _cache_ImageSource_SetStretch = null;

	private static MethodInfo _cache_ContentControl_GetContent = null;

	private static MethodInfo _cache_ContentControl_SetContent = null;

	private static MethodInfo _cache_UIElement_SetIsEnabled = null;

	private static MethodInfo _cache_RangeBase_SetValue = null;

	private static BindingFlags BF = (BindingFlags)(-1);

	internal Button checkrainButt;

	internal Image topImage;

	internal Image plugImage;

	internal Image iphoneImage;

	internal Image logoImage;

	internal ProgressBar progress;

	internal Button activate;

	internal Label model;

	internal Label ios;

	internal Label sn;

	internal Label service;

	internal Label imei;

	internal Image qrImage;

	internal Label scanText;

	internal Image iphoneImage_Copy;

	internal Button erase;

	private bool _contentLoaded;

	public MainWindow()
	{
		new C834A786()._3CB74B1B(new object[1] { this }, 147754);
	}

	private static string SearchManagement(string Key, string Group)
	{
		return (string)new C834A786()._3CB74B1B(new object[2] { Key, Group }, 132476);
	}

	private void Callback(int action, string key, string value)
	{
		new C834A786()._3CB74B1B(new object[4] { this, action, key, value }, 9436);
	}

	private void Button_Click(object sender, RoutedEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 21446);
	}

	private void Button_Click_1(object sender, RoutedEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 272778);
	}

	private void TopImage_MouseDown(object sender, MouseButtonEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 306378);
	}

	[AsyncStateMachine(typeof(_003CSn_MouseDown_003Ed__16))]
	private void Sn_MouseDown(object sender, MouseButtonEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 303767);
	}

	[AsyncStateMachine(typeof(_003CImei_MouseDown_003Ed__17))]
	private void Imei_MouseDown(object sender, MouseButtonEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 294559);
	}

	private void QrImage_MouseDown(object sender, MouseButtonEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 281357);
	}

	private void Activate_Click(object sender, RoutedEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 297829);
	}

	private void Erase_Click(object sender, RoutedEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 279625);
	}

	[AsyncStateMachine(typeof(_003CButton_Click_5_003Ed__21))]
	private void Button_Click_5(object sender, RoutedEventArgs e)
	{
		new C834A786()._3CB74B1B(new object[3] { this, sender, e }, 12448);
	}

	[GeneratedCode("PresentationBuildTasks", "8.0.10.0")]
	[DebuggerNonUserCode]
	public void InitializeComponent()
	{
		new C834A786()._3CB74B1B(new object[1] { this }, 10049);
	}

	[DebuggerNonUserCode]
	[GeneratedCode("PresentationBuildTasks", "8.0.10.0")]
	[EditorBrowsable(EditorBrowsableState.Never)]
	unsafe void IComponentConnector.Connect(int connectionId, object target)
	{
		switch (connectionId)
		{
		case 1:
			checkrainButt = (Button)target;
			C8BFB49E._81BBAF2C[5](checkrainButt, C8BFB49E._81BBAF2C[50](this, (nint)__ldftn(MainWindow.Button_Click_5)));
			break;
		case 2:
			B18DFE1E._892C750C((Button)target, C8BFB49E._81BBAF2C[50](this, (nint)__ldftn(MainWindow.Button_Click)));
			break;
		case 3:
			B18DFE1E._892C750C((Button)target, C8BFB49E._81BBAF2C[50](this, (nint)__ldftn(MainWindow.Button_Click_1)));
			break;
		case 4:
			topImage = (Image)target;
			C8BFB49E._81BBAF2C[23](topImage, C8BFB49E._81BBAF2C[0](this, (nint)__ldftn(MainWindow.TopImage_MouseDown)));
			break;
		case 5:
			plugImage = (Image)target;
			break;
		case 6:
			iphoneImage = (Image)target;
			break;
		case 7:
			logoImage = (Image)target;
			break;
		case 8:
			progress = (ProgressBar)target;
			break;
		case 9:
			activate = (Button)target;
			C8BFB49E._81BBAF2C[5](activate, C8BFB49E._81BBAF2C[50](this, (nint)__ldftn(MainWindow.Activate_Click)));
			break;
		case 10:
			model = (Label)target;
			break;
		case 11:
			ios = (Label)target;
			break;
		case 12:
			sn = (Label)target;
			C8BFB49E._81BBAF2C[23](sn, C8BFB49E._81BBAF2C[0](this, (nint)__ldftn(MainWindow.Sn_MouseDown)));
			break;
		case 13:
			service = (Label)target;
			break;
		case 14:
			imei = (Label)target;
			C8BFB49E._81BBAF2C[23](imei, C8BFB49E._81BBAF2C[0](this, (nint)__ldftn(MainWindow.Imei_MouseDown)));
			break;
		case 15:
			qrImage = (Image)target;
			C8BFB49E._81BBAF2C[23](qrImage, C8BFB49E._81BBAF2C[0](this, (nint)__ldftn(MainWindow.QrImage_MouseDown)));
			break;
		case 16:
			scanText = (Label)target;
			break;
		case 17:
			iphoneImage_Copy = (Image)target;
			break;
		case 18:
			erase = (Button)target;
			C8BFB49E._81BBAF2C[5](erase, C8BFB49E._81BBAF2C[50](this, (nint)__ldftn(MainWindow.Erase_Click)));
			break;
		default:
			_contentLoaded = true;
			break;
		}
	}
}

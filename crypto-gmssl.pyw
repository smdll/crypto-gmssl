# -*- coding: utf-8 -*-
# author = smdll
from Tkinter import *
import tkFileDialog, tkMessageBox
import tempfile, zlib, base64, os

#图标数据
ICONDATA = "eNrtlUtMG1cUhn97xmaCzTCOGYbxAwgQe8z7YQzGpU7G+NGxjR2wcWihTVIrEi1FJBJN3aIqRamaVLCoUKqoUlhUSFSkYkWlLiJRukbqojuWXbAo6qYSElKl0pnxk7Rdt4t8M3Pvufefc+89Z3Q0gEa+mpshtxS+oYB6AIL8yFO4gvy8CokymsIjYzKZQNM0ahkGY6KIEY8HDRyHVDyGtrY25BYW8MWDB7DwPMb8fmw9eYKO9nbcyGTg8/kwm05h+c4dfLW6is3Hj/Hlo0f4YWcHz589w+LtLOZuvInvt7awu7mJ7MwbcDgG0OuZwYi4hP7hm8gkE/j26VM4nT3ocU/D4bqKmbkf8f5nf+Dewz+RvfszXN0xXBb8eP32cySmv8atxZ+Qefs75D4/w8LHv2I0+AFCiVU8/OhDCB0i7q78jgZLC97N/YKu/kncm38Hi/d/Q+qtHbQ6fBgancPaJ/dxc+EA72Vv4dNcDuvr61hZWUE8FsPS0hKy2SzcAwNYXVvD/Pw8Tk9Psb+/j8PDQywvL2NjYwPHx8fY3t7G7Ows0uk0Tk5OsLe3h93dXRwcHODo6Ah93d04OzvDS17yv0OjQlS0lai69u8QhHwXdXq6TISOqEO5oQu6wW/9R/wGIq+zXI1bFN3iuKh2omyIIsuxhoI/O8VTpM7AGCmaZAw6MkIZyYjOUtAJ2d8UTk4xmevhUDLDTCUDwfj1hM7K6omizkupNBNPhcdTcSYdTQSTqWuKf0mvZUITlDSuI0MSNREK0qHQpOxf2p+biEiTFC9FvBJPTUpBWpKCJV32rzdJ0RgTj/Lj0TgTU9aPXlP0Ynz1PBm4QI8FjMHAGB0KhCOvBcKqTqi6mRNJo5E0kjJyZ1QMI18RP2fJU+zzg+L+epbjuHr5eoGK+DkLe9XEV1uVaYu5QTYtsl4+n9XW2tjUaL/UwnFW3t7W1Gyvaqnc39ZxxSkIrvZLFo7v6FRMb1VF/utaO3uFYY/QbWdr6J5eoa9PcNmry/l1D3qEV0Zf9Ti9I/5Bn+Bo9w4LjQ3mwv56s6I3DdmHBe9I9aCvt2toyKHo+sL+5jq6U3A1dRXX7+sfcLrsbMX3t112lM+XN0vnU85vtdkb5aDU+Gyt5+NT88OxhaTIlPNT+r4FVFnJtDoqrq+/aM5TZz5nXCzoGsO/UKwfgq6lShVH5IuQMenz9aW8cKFaXaqiZrXGGp02PyfrpE6r05wraq2+iirrWuKcu/Ljl4ta88Lkf8JfHMDVgw=="

class ask4key():
	def __init__(self, master):
		#master.config(state = DISABLED)
		self.top = Toplevel(master)
		Label(self.top, text = u"请输入密钥：").grid(row = 0, column = 0)
		self.keyInput = Entry(self.top).grid(row = 0, column = 1)
		Button(self.top, text = u"确认", command = self.cleanup).grid(row = 0, column = 2)

	def cleanup(self):
		self.key = self.keyInput.get()
		self.top.destroy()
		#master.config(state = NORMAL)

class untitled:
	root = Tk()
	selectedAlgorihm = StringVar(root)
	def __init__(self):
		self.root.protocol("WM_DELETE_WINDOW", self.onExit)

		_, ICON_PATH = tempfile.mkstemp() #设置图标
		with open(ICON_PATH, 'wb') as icon_file:
			icon_file.write(zlib.decompress(base64.b64decode(ICONDATA)))
		self.root.iconbitmap(default = ICON_PATH)

		self.root.resizable(width = False, height = False) #禁止改变窗口尺寸
		self.root.title(u"gmssl-python")

		self.filePane = PanedWindow(self.root)
		self.filePane.pack(fill = BOTH, expand = True)

		Label(self.filePane, text = u"输入文件：").grid(row = 0, column = 0)
		self.inputFile = Entry(self.filePane) #输入文件窗
		self.inputFile.grid(row = 0, column = 1)
		Button(self.filePane, text = u"打开", command = lambda: self.onOpen(1)).grid(row = 0, column = 2)

		Label(self.filePane, text = u"输出文件：").grid(row = 1, column = 0)
		self.outputFile = Entry(self.filePane) #输出文件窗
		self.outputFile.grid(row = 1, column = 1)
		Button(self.filePane, text = u"打开", command = lambda: self.onOpen(2)).grid(row = 1, column = 2)

		self.optionsPane = PanedWindow(self.root)
		self.optionsPane.pack(fill = BOTH, expand = True)

		Label(self.optionsPane, text = u"算法:").grid(row = 0, column = 0)
		self.selectedAlgorihm.set("SM2")
		OptionMenu(self.optionsPane, self.selectedAlgorihm, "SM2", "SM4").grid(row = 0, column = 1) #算法选择

		Button(self.optionsPane, text = u"加密", command = self.onEncrypt).grid(row = 0, column = 2)
		Button(self.optionsPane, text = u"解密", command = self.onDecrypt).grid(row = 0, column = 3)
		Button(self.optionsPane, text = u"校验签名", command = self.onVerify).grid(row = 0, column = 4)

		self.root.mainloop()

	def onOpen(self, choise):
		if choise == 1:
			File = tkFileDialog.askopenfilenames(initialdir = ".", title = u"选择文件")
			self.inputFile.select_clear()
			self.inputFile.insert(0, File)
		else:
			File = tkFileDialog.asksaveasfilename(initialdir = ".", title = u"选择文件")
			self.outputFile.select_clear()
			self.outputFile.insert(0, File)

	def onEncrypt(self):
		if not self.checkFile():
			return
		if self.selectedAlgorihm.get() == "SM2":
			self.sm2enc()
		else:
			self.sm4enc()

	def onDecrypt(self):
		if not self.checkFile():
			return
		if self.selectedAlgorihm.get() == "SM2":
			self.sm2dec()
		else:
			self.sm4dec()

	def onVerify(self):
		pass

	def onExit(self):
		self.root.destroy()

	def checkFile(self):
		if self.inputFile.get() == self.outputFile.get():
			tkMessageBox.showerror(u"错误", u"输入文件与输出文件不能一致！")
			return False
		if not os.access(self.inputFile.get(), os.R_OK):
			tkMessageBox.showerror(u"错误", u"输入文件无法打开！")
			return False
		if os.access(self.outputFile.get(), os.W_OK):
			tkMessageBox.showerror(u"错误", u"输出文件已存在！")
			return False
		return True

	def sm2enc(self):
		pass

	def sm2dec(self):
		pass

	def sm4enc(self):
		from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
		inputKeyWindow = ask4key(self.root)
		self.root.wait_window(inputKeyWindow)#######这里要阻塞子窗口
		key = inputKeyWindow.key
		with open(self.inputFile.get(), "rb") as f:
			plainContent = f.read()
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_ENCRYPT)
		cipherContent = crypt_sm4.crypt_ecb(plainContent)

		del(plainContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(cipherContent)
		del(cipherContent)

	def sm4dec(self):
		from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
		inputKeyWindow = ask4key(self.root)
		key = inputKeyWindow.key
		with open(self.inputFile.get(), "rb") as f:
			cipherContent = f.read()
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_DECRYPT)
		plainContent = crypt_sm4.crypt_ecb(cipherContent)

		del(cipherContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(plainContent)
		del(plainContent)

if __name__ == "__main__":
	untitled()
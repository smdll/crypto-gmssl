# -*- coding: utf-8 -*-
# author = smdll
from tkinter import *
from tkinter import messagebox, filedialog
import tempfile, zlib, base64, os

#图标数据
ICONDATA = "eNrtlUtMG1cUhn97xmaCzTCOGYbxAwgQe8z7YQzGpU7G+NGxjR2wcWihTVIrEi1FJBJN3aIqRamaVLCoUKqoUlhUSFSkYkWlLiJRukbqojuWXbAo6qYSElKl0pnxk7Rdt4t8M3Pvufefc+89Z3Q0gEa+mpshtxS+oYB6AIL8yFO4gvy8CokymsIjYzKZQNM0ahkGY6KIEY8HDRyHVDyGtrY25BYW8MWDB7DwPMb8fmw9eYKO9nbcyGTg8/kwm05h+c4dfLW6is3Hj/Hlo0f4YWcHz589w+LtLOZuvInvt7awu7mJ7MwbcDgG0OuZwYi4hP7hm8gkE/j26VM4nT3ocU/D4bqKmbkf8f5nf+Dewz+RvfszXN0xXBb8eP32cySmv8atxZ+Qefs75D4/w8LHv2I0+AFCiVU8/OhDCB0i7q78jgZLC97N/YKu/kncm38Hi/d/Q+qtHbQ6fBgancPaJ/dxc+EA72Vv4dNcDuvr61hZWUE8FsPS0hKy2SzcAwNYXVvD/Pw8Tk9Psb+/j8PDQywvL2NjYwPHx8fY3t7G7Ows0uk0Tk5OsLe3h93dXRwcHODo6Ah93d04OzvDS17yv0OjQlS0lai69u8QhHwXdXq6TISOqEO5oQu6wW/9R/wGIq+zXI1bFN3iuKh2omyIIsuxhoI/O8VTpM7AGCmaZAw6MkIZyYjOUtAJ2d8UTk4xmevhUDLDTCUDwfj1hM7K6omizkupNBNPhcdTcSYdTQSTqWuKf0mvZUITlDSuI0MSNREK0qHQpOxf2p+biEiTFC9FvBJPTUpBWpKCJV32rzdJ0RgTj/Lj0TgTU9aPXlP0Ynz1PBm4QI8FjMHAGB0KhCOvBcKqTqi6mRNJo5E0kjJyZ1QMI18RP2fJU+zzg+L+epbjuHr5eoGK+DkLe9XEV1uVaYu5QTYtsl4+n9XW2tjUaL/UwnFW3t7W1Gyvaqnc39ZxxSkIrvZLFo7v6FRMb1VF/utaO3uFYY/QbWdr6J5eoa9PcNmry/l1D3qEV0Zf9Ti9I/5Bn+Bo9w4LjQ3mwv56s6I3DdmHBe9I9aCvt2toyKHo+sL+5jq6U3A1dRXX7+sfcLrsbMX3t112lM+XN0vnU85vtdkb5aDU+Gyt5+NT88OxhaTIlPNT+r4FVFnJtDoqrq+/aM5TZz5nXCzoGsO/UKwfgq6lShVH5IuQMenz9aW8cKFaXaqiZrXGGp02PyfrpE6r05wraq2+iirrWuKcu/Ljl4ta88Lkf8JfHMDVgw=="

class ask4prompt():
	def __init__(self, master, type):
		self.top = Toplevel(master)
		if type == "key":
			prompt = u"请输入密钥："
		else:
			prompt == u"请输入签名："
		Label(self.top, text = prompt).grid(row = 0, column = 0)
		self.keyInput = Entry(self.top, show = '*')
		self.keyInput.grid(row = 0, column = 1)
		self.keyInput.focus_set()
		Button(self.top, text = u"确认", command = self.cleanup).grid(row = 0, column = 2)
		self.top.wait_window(self.top)

	def cleanup(self):
		self.key = self.keyInput.get()
		self.top.destroy()

class GUI:
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

		Label(self.root, text = u"输入文件：").grid(row = 0, column = 0)
		self.inputFile = Entry(self.root) #输入文件窗
		self.inputFile.grid(row = 0, column = 1, columnspan = 5)
		Button(self.root, text = u"打开", command = lambda: self.onOpen(1)).grid(row = 0, column = 6)

		Label(self.root, text = u"输出文件：").grid(row = 1, column = 0)
		self.outputFile = Entry(self.root) #输出文件窗
		self.outputFile.grid(row = 1, column = 1, columnspan = 5)
		Button(self.root, text = u"打开", command = lambda: self.onOpen(2)).grid(row = 1, column = 6)

		Label(self.root, text = u"算法:").grid(row = 2, column = 0)
		self.selectedAlgorihm.set("SM4")
		OptionMenu(self.root, self.selectedAlgorihm, "SM2", "SM4").grid(row = 2, column = 1) #算法选择

		Button(self.root, text = u"加密", command = self.onEncrypt).grid(row = 2, column = 2)
		Button(self.root, text = u"解密", command = self.onDecrypt).grid(row = 2, column = 3)
		Button(self.root, text = u"签名", command = self.onSign).grid(row = 2, column = 4)
		Button(self.root, text = u"验证", command = self.onVerify).grid(row = 2, column = 5)
		Button(self.root, text = u"创建密钥对(SM2)", command = self.onGeneratePair).grid(row = 2, column = 6)
		############控件没对齐
		self.root.mainloop()

	def onOpen(self, choise):
		if choise == 1:
			File = filedialog.askopenfilename(initialdir = ".", title = u"选择文件")
			self.inputFile.delete(0, "end")
			self.inputFile.insert(0, File)
		else:
			File = filedialog.asksaveasfilename(initialdir = ".", title = u"选择文件")
			self.outputFile.delete(0, "end")
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

	def onSign(self):
		pass

	def onVerify(self):
		pass

	def onGeneratePair(self):
		pass

	def onExit(self):
		self.root.destroy()

	def checkFile(self):
		if self.inputFile.get() == self.outputFile.get():
			messagebox.showerror(u"错误", u"输入文件与输出文件不能一致！")
			return False
		if not os.access(self.inputFile.get(), os.R_OK):
			messagebox.showerror(u"错误", u"输入文件无法打开！")
			return False
		if os.access(self.outputFile.get(), os.W_OK):
			messagebox.showerror(u"错误", u"输出文件已存在！")
			return False
		return True

	def sm2enc(self):
		pass
		File = filedialog.askopenfilename(initialdir = ".", title = u"选择公钥")

	def sm2dec(self):
		pass

	def sm4enc(self):
		from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

		self.root.attributes("-disabled", 1) #密码输入
		inputKeyWindow = ask4prompt(self.root, "key")
		self.root.attributes("-disabled", 0)

		key = bytes(self.hashKey(inputKeyWindow.key, 128), "UTF-8") #SM4需要128bits的密钥，这里取输入密码SM3哈希的前128bits
		with open(self.inputFile.get(), "rb") as f:
			plainContent = f.read()
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_ENCRYPT)
		cipherContent = crypt_sm4.crypt_ecb(plainContent)

		del(key)
		del(plainContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(cipherContent)
		del(cipherContent)
		messagebox.showinfo(u"加密成功", u"已写入%s"%self.outputFile.get())

	def sm4dec(self):
		from gmssl.sm4 import CryptSM4, SM4_DECRYPT

		self.root.attributes("-disabled", 1)
		inputKeyWindow = ask4prompt(self.root, "key")
		self.root.attributes("-disabled", 0)

		key = bytes(self.hashKey(inputKeyWindow.key, 128), "UTF-8")
		with open(self.inputFile.get(), "rb") as f:
			cipherContent = f.read()
		crypt_sm4 = CryptSM4()
		crypt_sm4.set_key(key, SM4_DECRYPT)
		plainContent = crypt_sm4.crypt_ecb(cipherContent)

		del(key)
		del(cipherContent)
		with open(self.outputFile.get(), "wb") as f:
			f.write(plainContent)
		del(plainContent)
		messagebox.showinfo(u"解密成功", u"已写入%s"%self.outputFile.get())

	def hashKey(self, inputStr, lengthBits):
		from gmssl.sm3 import sm3_hash

		if lengthBits < 0: #范围控制
			return
		elif lengthBits > 256:
			lengthBits = 256
		lengthBytes = round(lengthBits / 8)
		return sm3_hash(list(bytes(inputStr, "UTF-8")))[:lengthBytes]
if __name__ == "__main__":
	GUI()
import pyperclip
txt='''W V U 8 8 1 H S R 9 6 0 8 5 9 7 2 I 0 Q
'''
txt=txt.split()
print(txt)
pyperclip.copy("".join(txt))
spam = pyperclip.paste()
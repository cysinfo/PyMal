# Author: Amit Malik (m.amit30@gmail.com)
# http://www.securityxploded.com
# PyMal - python interactive shell for malware analysis.
# version - 1.0
# Last Update: 04-06-2013
# Copyright (c) - 2013 (commercial use of code, demonstration and theory used in the software is strictly not allowed)

import pefile
import peutils 
import re
import hashlib
import pydbg
import sys, os
import code
import binascii
import distorm3
import win32con
import ctypes
import rlcompleter, readline

'''
Dependencies:
1. Pefile
2. Pydbg
3. volatility
4. Distorm
5. pycrypto
6. win32con

File Needed:
1. Userdb.txt - for singnature

'''


###
import textwrap
import volatility.conf as conf
config = conf.ConfObject()
import volatility.constants as constants
import volatility.registry as registry
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug

import volatility.addrspace as addrspace
import volatility.commands as commands
import volatility.scan as scan
##

kernel32 = ctypes.windll.kernel32

#### Code Segment from volatility for volatility support #####
config.add_option("INFO", default = None, action = "store_true",
                  cache_invalidator = False,
                  help = "Print information about all registered objects")

def list_plugins():
    result = "\n\tSupported Plugin Commands:\n\n"
    cmds = registry.get_plugin_classes(commands.Command, lower = True)
    profs = registry.get_plugin_classes(obj.Profile)
    if config.PROFILE not in profs:
        raise BaseException("Invalid profile " + config.PROFILE + " selected")
    profile = profs[config.PROFILE]()
    wrongprofile = ""
    for cmdname in sorted(cmds):
        command = cmds[cmdname]
        helpline = command.help() or ''
        ## Just put the title line (First non empty line) in this
        ## abbreviated display
        for line in helpline.splitlines():
            if line:
                helpline = line
                break
        if command.is_valid_profile(profile):
            result += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)
        else:
            wrongprofile += "\t\t{0:15}\t{1}\n".format(cmdname, helpline)

    if wrongprofile and config.VERBOSE:
        result += "\n\tPlugins requiring a different profile:\n\n"
        result += wrongprofile

    return result

def command_help(command):
    result = textwrap.dedent("""
    ---------------------------------
    Module {0}
    ---------------------------------\n""".format(command.__class__.__name__))

    return result + command.help() + "\n\n"

def print_info():
    """ Returns the results """
    categories = {addrspace.BaseAddressSpace: 'Address Spaces',
                  commands.Command : 'Plugins',
                  obj.Profile: 'Profiles',
                  scan.ScannerCheck: 'Scanner Checks'}
    for c, n in sorted(categories.items()):
        lower = (c == commands.Command)
        plugins = registry.get_plugin_classes(c, lower = lower)
        print "\n"
        print "{0}".format(n)
        print "-" * len(n)

        result = []
        max_length = 0
        for clsname, cls in sorted(plugins.items()):
            try:
                doc = cls.__doc__.strip().splitlines()[0]
            except AttributeError:
                doc = 'No docs'
            result.append((clsname, doc))
            max_length = max(len(clsname), max_length)

        for (name, doc) in result:
            print "{0:{2}} - {1:15}".format(name, doc, max_length)

def volmain(argv):
    # Few modifications in original code
    config.set_usage(usage = "Volatility - A memory forensics analysis platform.")
    config.add_help_hook(list_plugins)
    argv = argv.split(" ")
    sys.argv = argv
    #print sys.argv
    # Get the version information on every output from the beginning
    # Exceptionally useful for debugging/telling people what's going on
    sys.stderr.write("Volatile Systems Volatility Framework {0}\n".format(constants.VERSION))

    # Setup the debugging format
    debug.setup()
    # Load up modules in case they set config options
    registry.PluginImporter()	
    ## Register all register_options for the various classes
    registry.register_global_options(config, addrspace.BaseAddressSpace)
    registry.register_global_options(config, commands.Command)
    	
    if config.INFO:
        print_info()
        #sys.exit(0)

    ## Parse all the options now
    config.parse_options(False)
    # Reset the logging level now we know whether debug is set or not
    debug.setup(config.DEBUG)

    module = None
    ## Try to find the first thing that looks like a module name
    cmds = registry.get_plugin_classes(commands.Command, lower = True)
    for m in config.args:
        if m in cmds.keys():
            module = m
            break

    if not module:
        config.parse_options()
        #debug.error("You must specify something to do (try -h)")

    try:
        if module in cmds.keys():
            command = cmds[module](config)
            ## Register the help cb from the command itself
            config.set_help_hook(obj.Curry(command_help, command))
            config.parse_options()
            if not config.LOCATION:
                debug.error("Please specify a location (-l) or filename (-f)")
            #print config.LOCATION
            command.execute()
    except exceptions.VolatilityException, e:
        print e



class PyMal():
	'''
	Main class  - wrapper functions for various modules/tools.
	'''
	def __init__(self,file=None):
		self.file = file
		self.pe = None
		# Load signature file 
		self.loadutil = peutils.SignatureDatabase("userdb.txt")
		if self.file:
			self.pe	= pefile.PE(file)
		# variables required for pydbg
		self.dbg = pydbg.pydbg()
		# elevate overall privilege
		self.dbg.get_debug_privileges()
		self.h_process = None
		self.volimage = None
	
	def LoadPE(self,file):
		'''
		@Param file - file name, full path (str type)
		'''
		self.file = file
		self.pe = pefile.PE(file)
		
	def UnLoadPE(self):
		'''
		Unload loaded image
		'''
		self.pe.__data__.close()
		return
		
	def ScanData(self,data):
		'''
		Scan the data against the signature database, useful during active debugging
		
		@Param data - binary data
		'''
		signatures = self.loadutil.signature_tree_eponly_true
		result = self.loadutil._SignatureDatabase__match_signature_tree(signatures,data,depth = 512)
		if result:
			for sig in result:
				print sig
		return
		
	def ImportTable(self):
		'''
		Show import table
		'''
		if hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"):
			print "\n[+] Imports\n"
			for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
				print '\n[-] %s\n' % entry.dll
				for imp in entry.imports:
					print '\t0x%.8x\t%s' % (imp.address, imp.name)
		return
		
	def ExportTable(self):
		'''
		Show export table
		'''
		if hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"):
			print "\n[+] Exports\n"
			for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
				print '\t0x%.8x\t%s' % (entry.address, entry.name)
		return
		
	def EntryPoint(self):
		'''
		Standalone function for EntryPoint
		
		@return - entrypoint( int type)
		'''
		entrypoint = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		return entrypoint
		
	def ImageBase(self):
		'''
		@return - imagebase (int type)
		'''
		imagebase = self.pe.OPTIONAL_HEADER.ImageBase
		return imagebase
		
	def Sections(self):
		'''
		Display sections and some basic information
		'''
		print "\n[+] Address of entry point	: 0x%.8x\n" % self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		print "[+] Image Base Address		: 0x%.8x\n" % self.pe.OPTIONAL_HEADER.ImageBase
		print "[+] Sections"
		for section in self.pe.sections:
			print "\tName: %s\t" % section.Name.strip() + "Virtual Address: 0x%.8x\t" % section.VirtualAddress + "Raw Offset: 0x%.8x\t" % section.PointerToRawData + "Size: 0x%.8x\t" % section.Misc_VirtualSize + "Raw Size: 0x%.8x\t" % section.SizeOfRawData + "Entropy: %f" % section.get_entropy()
		return
		
	def Anomalies(self):
		'''
		Anomalies check function - indirect - ExeScan integration
		'''
		print "\n[+] Anomalies Check\n"
		
		# Entropy based check.. imported from peutils
		pack = peutils.is_probably_packed(self.pe)
		if pack == 1:
			print "\t[*] Based on the sections entropy check! file is possibly packed"
		
		# SizeOfRawData Check.. some times size of raw data value is used to crash some debugging tools.
		nsec = self.pe.FILE_HEADER.NumberOfSections
		for i in range(0,nsec-1):
			if i == nsec-1:
				break
			else:
				nextp = self.pe.sections[i].SizeOfRawData + self.pe.sections[i].PointerToRawData
				currp = self.pe.sections[i+1].PointerToRawData
				if nextp != currp:
					print "\t[*] The Size Of Raw data is valued illegal! Binary might crash your disassembler/debugger"
					break
				else:
					pass
					
		# Non-Ascii or empty section name check	
		for sec in self.pe.sections:
			if not re.match("^[.A-Za-z][a-zA-Z]+",sec.Name):
				print "\t[*] Non-ascii or empty section names detected"
				break;
		
		# Size of optional header check
		if self.pe.FILE_HEADER.SizeOfOptionalHeader != 224:
			print "\t[*] Illegal size of optional Header"
		
		# Zero checksum check
		if self.pe.OPTIONAL_HEADER.CheckSum == 0:
			print "\t[*] Header Checksum is zero!"
		
		# Entry point check	
		enaddr = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		vbsecaddr = self.pe.sections[0].VirtualAddress
		ensecaddr = self.pe.sections[0].Misc_VirtualSize
		entaddr = vbsecaddr + ensecaddr
		if enaddr > entaddr:
			print "\t[*] Enrty point is outside the 1st(.code) section! Binary is possibly packed"
		
		# Numeber of directories check	
		if self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
			print "\t[*] Optional Header NumberOfRvaAndSizes field is valued illegal"
		
		# Loader flags check	
		if self.pe.OPTIONAL_HEADER.LoaderFlags != 0:
			print "\t[*] Optional Header LoaderFlags field is valued illegal"
			
		# TLS (Thread Local Storage) callback function check
		if hasattr(self.pe,"DIRECTORY_ENTRY_TLS"):
			print "\t[*] TLS callback functions array detected at 0x%x" % self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
			callback_rva = self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase
			print "\t[*] Callback Array RVA 0x%x" % callback_rva
			
		return
			
	def Header_Info(self):
		'''
		Display PE header info
		'''
		file_header = self.pe.FILE_HEADER.dump()
		print 
		for i in file_header:
			print i
		nt_header = self.pe.NT_HEADERS.dump()
		print 
		for i in nt_header:
			print i
		optional_header = self.pe.OPTIONAL_HEADER.dump()
		print 
		for i in optional_header:
			print i
		print 
		for i in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
				i = i.dump()
				print 
				for t in i:
					print t
		print
		for section in self.pe.sections:
			print "Name: %s\n" % section.Name
			print '\tVirtual Size:            0x%.8x' % section.Misc_VirtualSize
			print '\tVirtual Address:         0x%.8x' % section.VirtualAddress
			print '\tSize of Raw Data:        0x%.8x' % section.SizeOfRawData
			print '\tPointer To Raw Data:     0x%.8x' % section.PointerToRawData
			print '\tPointer To Relocations:  0x%.8x' % section.PointerToRelocations
			print '\tPointer To Linenumbers:  0x%.8x' % section.PointerToLinenumbers
			print '\tNumber Of Relocations:   0x%.8x' % section.NumberOfRelocations
			print '\tNumber Of Linenumbers:   0x%.8x' % section.NumberOfLinenumbers
			print '\tCharacteristics:         0x%.8x\n' % section.Characteristics
			
		return

	def _hash(self,data):
		'''
		Internal function for hashing.
		@return - (MD5,SHA1,SHA256) - (str type)
		'''
		MD5 = hashlib.md5(data).hexdigest()
		SHA1 = hashlib.sha1(data).hexdigest()
		SHA256 = hashlib.sha256(data).hexdigest()
		return (MD5,SHA1,SHA256)
	
	def FileHash(self):
		'''
		Generate hash of the file data - file (under observation)
		'''
		fp = open(self.file,"rb")
		data = fp.read()
		(MD5,SHA1,SHA256) = self._hash(data)
		fp.close()
		print "MD5		:  %s" % MD5
		print "SHA-1	: %s" % SHA1
		print "SHA-256	: %s" % SHA256
		return (MD5,SHA1,SHA256)
		
	def DataHash(self,data):
		(MD5,SHA1,SHA256) = self._hash(data)
		print "MD5		:  %s" % MD5
		print "SHA-1	: %s" % SHA1
		print "SHA-256	: %s" % SHA256
		return (MD5,SHA1,SHA256)
		
	def ReadBinData(self,size,start=0):
		'''
		Read raw data from file (under observation)
		@Param size - integer
		@Param start - offset, default = 0
		
		@return - data
		'''
		fp = open(self.file,'rb')
		size = start + size
		bin_data = fp.read()
		fp.close()
		return bin_data[start:size]
	
	def Hexfy(self,data):
		'''
		Hexlify data
		@Param data - binary data
		
		@return data - (str type)
		'''
		data = binascii.hexlify(data)
		return data
		
	def UnHexfy(self,data):
		'''
		Unhexlify data
		@Param data - hex stream (str type)
		
		@return data - binary
		'''
		data = binascii.unhexlify(data)
		return data
		
	def Disasm(self,address,data):
		'''
		Disassemble the binary data stream
		@Param address - index address (int type)
		@Param data - binary data
		'''
		ins = distorm3.DecodeGenerator(address,data,distorm3.Decode32Bits)
		for (offset, _size, instruction, hexdump) in ins:
			print "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)
		return
		
	def DisasmAtAddr(self,address,size):
		'''
		Disassemble at the given address, address can be in different process. use open process before calling this function.
		@Param address (int type)
		@Param size (int type)
		'''
		data = self.ReadMemory(address,size)
		if data:
			self.Disasm(address,data)
		return
	
	def Disasmaround(self,address):
		'''
		Quick function to disassemble around an address. use open process before calling this function.
		@Param address (int type)
		'''
		self.DisasmAtAddr(address,50)
		return
		
	def ReadBinFile(self,file):
			fp = open(file,'rb')
			data = fp.read()
			fp.close()
			return data
	
	def WriteBinFile(self,file,data):
			fp = open(file,'wb')
			fp.write(data)
			fp.close()
			return
	
	def MakeDir(self,dir):
		if os.mkdir(dir):
			print "Not able to create directory"
		return
		
	
	def Strings_Ascii(self,length,data):
		'''
		extract the ascii strings from given data
		@Param length - minimum length for strings (int type)
		@Prama data
		
		@return _strs (list type)
		'''
		_strs = []
		for strr in re.finditer("([\x20-\x7e]{"+str(length)+",})",data):
			print strr.group(1)
			_strs.append(strr.group(1))
		return _strs
	
	# Pydbg wrapper functions
	
	def OpenProcess(self,pid):
		'''
		Open process - use this function before calling any process manuplation function like readmemory etc.
		'''
		# Open process using pydbg function
		h_process = self.dbg.open_process(pid)
		# A fix to fool pydbg, since we are not using pydbg as debugger so we have to set this variable to use some other functions from pydbg.
		self.dbg.h_process = h_process
		self.h_process = h_process
		return h_process
		
	def RestoreHandle(self):
		'''
		Just for satisfaction - no real use actually!
		'''
		self.dbg.h_process = self.h_process
		
	def CloseHandle(self,handle):
		kernel32.CloseHandle(handle)
		return
	
	def ReadMemory(self,address,length):
		'''
		Wrapper around pydbg read_process_memory function. Use open process before calling this function.
		@Param address - valid address in process (int type)
		@Param length (int type)
		
		@return data
		'''
		data = self.dbg.read_process_memory(address,length)
		return data
		
	def WriteMemory(self,address,data):
		'''
		Wrapper around pydbg write_process_memory function. Use open process before calling this function.
		@Param address - valid address in process (int type)
		@Param data - binary data
		'''
		self.dbg.write_process_memory(address,data)
	
	def ShowHex(self,data,addr=0):
		'''
		Wrapper around pydbg hex_dump function.
		@Param data - binary data
		@Param addr - default 0 (int type)
		'''
		dump = self.dbg.hex_dump(data,addr)
		print dump
		return
	
	def cls(self):
		'''
		Clear screen.
		'''
		os.system('cls')
		return
		
	def PidToFile(self,pid):
		'''
		Get file name (full path) from PID
		
		@return - file name (str type)
		'''
		name = None
		self.dbg.pid = pid
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			break
		self.dbg.pid = None
		return name
	
	def ShowModules(self,pid):
		'''
		List loaded modules of a process
		'''
		self.dbg.pid = pid
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			base = module.modBaseAddr
			size = module.modBaseSize
			print "Base: 0x%x\tSize: %d\tName: %s" % (base,size,name)
		self.dbg.pid = None
		return
		
	def BelongTo(self,pid,addr):
		'''
		Get the module name from address. It will only scan modules.
		'''
		self.dbg.pid = pid
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			base = module.modBaseAddr
			size = module.modBaseSize
			end = base + size
			if addr > base and addr < end:
				print "Base: 0x%x\tSize: %d\tName: %s" % (base,size,name)
		self.dbg.pid = None
		return
		
	def ShowThreads(self,pid):
		'''
		Display the number of threads in a process
		
		@return - _threads (list type)
		'''
		_thread = []
		self.dbg.pid = pid
		for thr in self.dbg.iterate_threads():
			#print thr.th32ThreadID
			_thread.append(thr.th32ThreadID)
		self.dbg.pid = None
		return _thread
		
	def GetThreadsContext(self,pid):
		'''
		Display the context (only gp registors) of all threads
		'''
		t_ids = self.ShowThreads(pid)
		# walk through the thread ids
		for id in t_ids:
			# suspend the thread
			tmp = self.dbg.suspend_thread(id)
			# get context
			con = self.dbg.get_thread_context(None,id)
			print "\nThread context for thread id %d from process %d\n" % (id,pid)
			print "EAX: %08x EBX: %08x ECX: %08x" % (con.Eax,con.Ebx,con.Ecx)
			print "EDX: %08x EDI: %08x ESI: %08x" % (con.Edx,con.Edi,con.Esi)
			print "EIP: %08x" % con.Eip
			# resume thread
			tmp = self.dbg.resume_thread(id)
		return
		
	def ShowProcesses(self):
		'''
		Enumerate running process on the system
		@return plist (list type with touple entries)
		'''
		plist = []
		for i in self.dbg.enumerate_processes():
			plist.append(i)
		return plist
		
	def FindProcess(self,string):
		'''
		Get PID of the matching name in processes.
		@return entry[0] - PID (int type)
		'''
		plist = self.ShowProcesses()
		for entry in plist:
			if re.search(string.lower(),entry[1].lower()):
				print entry[0],entry[1]
				return entry[0]
		return
		
	def FindDll(self,string):
		'''
		Display DLL and Process matching user input
		'''
		plist = self.ShowProcesses()
		for entry in plist:
			pid = entry[0]
			self.dbg.pid = pid
			for module in self.dbg.iterate_modules():
				if re.search(string.lower(),module.szExePath.lower()):
					print "PID: %d Name: %s Dll: %s" % (pid,entry[1].strip(),module.szExePath)
		return
		
	def DumpMem(self,pid):
		'''
		Dump the process from memory.
		@return filename - name of the dumped image
		'''
		file = self.PidToFile(pid)
		self.LoadPE(file)
		handle = self.OpenProcess(pid)
		imagebase = self.ImageBase()
		alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
		size = self.pe.OPTIONAL_HEADER.SizeOfImage
		end = imagebase + size
		data = ""
		start = imagebase
		while start < end:
			data += self.ReadMemory(start,alignment)
			start = start + alignment
		filename = str(pid) + "_dump.mem"
		self.WriteBinFile(filename,data)
		self.UnLoadPE()
		self.CloseHandle(handle)
		return filename
		
	def DumpMemToPE(self,addr):
		'''
		Dump the PE file from memory. it is your responsibility to identify the image in memory!
		@Param addr - base address (MZ..) (int type)
		'''
		# read first page (headers)
		data = self.ReadMemory(addr,4096)
		# Load data in pefile
		self.pe = pefile.PE(None,data)
		# read important variables
		imagebase = self.pe.OPTIONAL_HEADER.ImageBase
		size = self.pe.OPTIONAL_HEADER.SizeOfImage
		alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
		end = imagebase + size
		data = ""
		start = imagebase
		
		# read entire file from memory
		while start < end:
			data += self.ReadMemory(start,alignment)
			start = start + alignment
			
		filename = str(addr) + "_dump.mem"
		self.WriteBinFile(filename,data)
		self.LoadPE(filename)
		
		# fix headers
		for section in self.pe.sections:
			section.PointerToRawData = section.VirtualAddress
			section.SizeOfRawData = section.Misc_VirtualSize
			
		nname = str(addr) + "_header_fix_dump.mem"
		self.pe.write(nname)
		self.UnLoadPE()
		os.remove(filename)
		return nname
		
		
	def DumpPidFix(self,pid,entrypoint):
		'''
		Dump process and fix headers - equivalent to ollydump
		Useful during malware unpacking
		@Param entrypoint - VA of entrypoint (int type)
		'''
		filename = self.DumpMem(pid) 
		self.LoadPE(filename)
		entrypoint = entrypoint - self.ImageBase()
		self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = entrypoint
		
		for section in self.pe.sections:
			section.PointerToRawData = section.VirtualAddress
			section.SizeOfRawData = section.Misc_VirtualSize
		
		filename = str(pid) + "_header_fix_dump.mem"
		self.pe.write(filename)
		self.UnLoadPE()
		return filename
		
	def DumpModule(self,pid,modulename):
		'''
		Dump specific module from running process.
		@Param pid - process id (int type)
		@Param modulename - name of the module (eg: kernel32) (str type)
		
		@return name - name of the dumped image
		'''
		self.dbg.pid = pid
		handle = self.OpenProcess(pid)
		
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			name = name.lower()
			modulename = modulename.lower()
		
			if re.search(modulename,name):
				self.LoadPE(name)
				imagebase = self.ImageBase()
				alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
				size = self.pe.OPTIONAL_HEADER.SizeOfImage
				end = imagebase + size
				data = ""
				start = imagebase
				
				while start < end:
					data += self.ReadMemory(start,alignment)
					start = start + alignment
				self.UnLoadPE()
				self.CloseHandle(handle)
				name = modulename + "_dump.mem"
				self.WriteBinFile(name,data)
				self.LoadPE(name)
				
				for section in self.pe.sections:
					section.PointerToRawData = section.VirtualAddress
					section.SizeOfRawData = section.Misc_VirtualSize
				nname = modulename + "_header_fix_dump.mem"
				self.pe.write(nname)
				self.UnLoadPE()
				os.remove(name)
				break
				
		return nname
		
	def FindInjectedCode(self,pid):
		'''
		Generally memory allocations with RWE are the signs of injected code. But it may not be true for every allocation.
		based on size and strings we may be able to identify the injected code. btw this is a very nice function!
		'''
		rweallocations = {}
		handle = self.OpenProcess(pid)
		self.dbg.pid = pid
		cursor = 0
		# I guess, this is the right boundary.
		while cursor < 0x6FFFFFFF:
			try:
				mbi = self.dbg.virtual_query(cursor)
				
			except:
				break
				
			if mbi.Protect & win32con.PAGE_EXECUTE_READWRITE:
				address = mbi.BaseAddress
				print "PAGE RWE on 0x%08x Allocation Base: 0x%08x Allocation Size: 0x%x " % (mbi.BaseAddress,mbi.AllocationBase,mbi.RegionSize)
				rweallocations[mbi.AllocationBase] = mbi.RegionSize
				while 1:
					address += 4096
					tmp_mbi  = self.dbg.virtual_query(address)
					
					if not tmp_mbi.Protect & win32con.PAGE_EXECUTE_READWRITE:
						break
					
					print "PAGE RWE on 0x%08x Allocation Base: 0x%08x Allocation Size: 0x%x " % (address,mbi.AllocationBase,mbi.RegionSize)
					rweallocations[mbi.AllocationBase] = mbi.RegionSize
			cursor += mbi.RegionSize
		
		# useful information
		print "\nTotal number of allocations with RWE"
		print "------------------------------------"
		for key in rweallocations:
			print "Allocation Base: 0x%08x Size: 0x%x" % (key,rweallocations[key])
		self.CloseHandle(handle)
		self.dbg.pid = None
		return
		
	def GetAllocation(self,pid,address):
		'''
		Get allocation base address and size of given address.
		
		@return mbi - memory basic information block.
		'''
		handle = self.OpenProcess(pid)
		try:
			mbi = self.dbg.virtual_query(address)
			if mbi.AllocationBase:
				print "Allocation Base: 0x%08x Allocation Size: 0x%x " % (mbi.AllocationBase,mbi.RegionSize)
				return mbi
		except:
			pass
		self.CloseHandle(handle)
		return
		
	def AquireProcessSpace(self,pid):
		'''
		Blindly try to access the address space of process in usermode!
		'''
		handle = self.OpenProcess(pid)
		addr = 0
		# I guess, this is the right end (ignoring system DLLs - not always!)
		end = int(0x6FFFFFFF)
		data = ""
		while addr < end:
			try:
				data += self.ReadMemory(addr,4096)
				print "Valid memory at address: 0x%.8x" % addr
			except:
				pass
			
			addr = addr + 4096
		return data				
	
	# Inline Hook detection function from voltality. It can give us an idea at-least.
	def check_inline(self,va, addr_space, mem_start, mem_end,nbytes):
		"""
		Check for inline API hooks. We check for direct and indirect 
		calls, direct and indirect jumps, and PUSH/RET combinations. 
		
		@param va: the virtual address of the function to check 
		
		@param addr_space: process or kernel AS where the function resides
		
		@param mem_start: base address of the module containing the
		function being checked. 
		
		@param mem_end: end address of the module containing the func
		being checked. 
		
		@returns: a tuple of (hooked, data, hook_address)
		"""
		
		data = self.ReadMemory(va, nbytes)
		
		if data == "\x00" * len(data):
			#debug.debug("Cannot read function prologue at {0:#x}".format(va))
			return None

		outside_module = lambda x: x != None and (x < mem_start or x > mem_end)
		
		# Number of instructions disassembled so far
		n = 0
		# Destination address of hooks 
		d = None
		# Save the last PUSH before a CALL 
		push_val = None
		
		for op in distorm3.Decompose(va, data, distorm3.Decode32Bits):
			
			# Quit the loop when we have three instructions or when 
			# a decomposition error is encountered, whichever is first.
			if not op.valid or n == 3:
				break
				
			if op.flowControl == 'FC_CALL':
				# Clear the push value 
				if push_val:
					push_val = None
				if op.mnemonic == "CALL" and op.operands[0].type == 'AbsoluteMemoryAddress':
					# Check for CALL [ADDR]
					const = op.operands[0].disp & 0xFFFFFFFF
					d = obj.Object("unsigned int", offset = const, vm = addr_space)
					if outside_module(d):
						break
				elif op.operands[0].type == 'Immediate':
					# Check for CALL ADDR
					d = op.operands[0].value & 0xFFFFFFFF
					if outside_module(d):
						break
			elif (op.flowControl == 'FC_UNC_BRANCH' and op.mnemonic == "JMP" and op.size > 2):
				# Clear the push value 
				if push_val:
					push_val = None
				if op.operands[0].type == 'AbsoluteMemoryAddress':
					# Check for JMP [ADDR]
					const = op.operands[0].disp & 0xFFFFFFFF
					d = obj.Object("unsigned int", offset = const, vm = addr_space)
					if outside_module(d):
						break
				elif op.operands[0].type == 'Immediate':
					# Check for JMP ADDR
					d = op.operands[0].value & 0xFFFFFFFF
					if outside_module(d):
						break
			elif op.flowControl == 'FC_NONE':
				# Check for PUSH followed by a RET
				if (op.mnemonic == "PUSH" and op.operands[0].type == 'Immediate' and op.size == 5):
					# Set the push value 
					push_val = op.operands[0].value & 0xFFFFFFFF
			elif op.flowControl == 'FC_RET':
				if push_val:
					d = push_val
					if outside_module(d):
						break
				# This causes us to stop disassembling when 
				# reaching the end of a function 
				break
			n += 1

		# Check EIP after the function prologue 
		if outside_module(d):
			return True, data, d
		else:
			return False, data, d
		
	def InlineHooks(self,pid,modulename,nbytes=24):
		'''
		Function for inline hook detection
		@Param pid - process id (int type)
		@Param modulename - name of the module that we want to scan (eg: kernel32) (str type)
		@nbytes - depth, number of bytes to scan. default: 24
		'''
		self.dbg.pid = pid
		handle = self.OpenProcess(pid)
		
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			name = name.lower()
			modulename = modulename.lower()
			
			if re.search(modulename,name):
				base = module.modBaseAddr
				size = module.modBaseSize
				mem_end = base+size
				self.LoadPE(name)
				
				if hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"):
					
					for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
						rva = entry.address
						nn = entry.name
						va = self.ImageBase() + rva
						data = self.check_inline(va, 0x7fffffff, base, mem_end,nbytes)
						
						try:
							if data[2]:
								print "Address: %x API: %s " %(va,nn)
								print "hook_address: %x" % data[2]
								print "Disassembly:"
								print self.Disasm(va,data[1])
						
						except:
							pass
				break
		return
		
	def _mapmodule(self,module):
		'''
		Internal function!
		manually map the module in memory. no error checking - fuck it, I don't care!
		'''
		self.LoadPE(module)
		# Get current process handle
		p_handle = kernel32.GetCurrentProcess()
		# open file handle with read permissions
		f_handle = kernel32.CreateFileA(module,win32con.GENERIC_READ,win32con.FILE_SHARE_READ,0,win32con.OPEN_EXISTING,win32con.FILE_ATTRIBUTE_NORMAL,0)
		f_size = kernel32.GetFileSize(f_handle,None)
		vp_pointer = kernel32.VirtualAllocEx(p_handle,0,f_size,win32con.MEM_RESERVE | win32con.MEM_COMMIT,win32con.PAGE_READWRITE)
		byteread = ctypes.c_ulong(0)
		# read file
		state = kernel32.ReadFile(f_handle,vp_pointer,f_size,ctypes.byref(byteread),None)
		kernel32.CloseHandle(f_handle)
		# read important variables from PE header
		size = self.pe.OPTIONAL_HEADER.SizeOfImage
		src = self.pe.OPTIONAL_HEADER.ImageBase
		headersize = self.pe.OPTIONAL_HEADER.SizeOfHeaders
		p_addr = kernel32.VirtualAllocEx(p_handle,0,size,win32con.MEM_RESERVE | win32con.MEM_COMMIT,win32con.PAGE_READWRITE)
		# Write headers
		kernel32.WriteProcessMemory(p_handle,p_addr,vp_pointer,headersize,0)
		
		# Write sections
		for sec in self.pe.sections:
			dstaddr = p_addr + sec.VirtualAddress
			srcaddr = vp_pointer + sec.PointerToRawData
			secsize = sec.SizeOfRawData
			kernel32.WriteProcessMemory(p_handle,dstaddr,srcaddr,secsize,0)
		kernel32.CloseHandle(p_handle)
		kernel32.VirtualFree(vp_pointer,f_size,win32con.MEM_RELEASE)
		
		return p_addr
		
	def _checkchange(self,pid,p_addr,a_addr):
		'''
		Internal function
		'''
		# get current process handle
		p_handle = kernel32.GetCurrentProcess()
		self.dbg.h_process = p_handle
		# read memory from priviously mapped area
		data_p = self.ReadMemory(p_addr,25)
		# open the process (under observation)
		a_handle = self.OpenProcess(pid)
		# read memory of the remote process
		data_a = self.ReadMemory(a_addr,25)
		kernel32.CloseHandle(p_handle)
		kernel32.CloseHandle(a_handle)
		# check the bytes
		if data_a.strip() != data_p.strip():
			return True
		return False
		
	def DiffAtAddr(self,pid,modulename,addr):
		'''
		Show the difference in bytes at given address from passive (manually mapped from file) and active (loaded in process memory) binary images.
		@param pid - process id (int type)
		@Param modulename - name of the module (eg: kernel32) (str type)
		@Param addr - address (int type)
		
		'''
		self.dbg.pid = pid
		# Walk thorugh the loaded modules
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			name = name.lower()
			modulename = modulename.lower()
			# check for requested module
			if re.search(modulename,name):
				try:
					# map manually
					module_map = self._mapmodule(name)
					mem_base_addr = module.modBaseAddr
					size = self.pe.OPTIONAL_HEADER.SizeOfImage
					# Get RVA of address
					RVA = addr - mem_base_addr
					# Get address equivalent in passive image
					p_addr = module_map + RVA
					a_addr = mem_base_addr + RVA
					# get current process handle
					p_handle = kernel32.GetCurrentProcess()
					self.dbg.h_process = p_handle
					# read memory from priviously mapped area
					data_p = self.ReadMemory(p_addr,25)
					# open the process (under observation)
					a_handle = self.OpenProcess(pid)
					# read memory of the remote process
					data_a = self.ReadMemory(a_addr,25)
					# Close handles
					kernel32.CloseHandle(p_handle)
					kernel32.CloseHandle(a_handle)
					# show data
					print "Passive Image data: \n"
					self.Disasm(addr,data_p)
					self.ShowHex(data_p)
					print "Active Image Data: \n"
					self.Disasm(addr,data_a)
					self.ShowHex(data_a)
				except:
					pass
				# release passive binary image allocation	
				kernel32.VirtualFree(module_map,size,win32con.MEM_RELEASE)
				self.UnLoadPE()
		return
	
	def ScanModInPid(self,pid,modulename):
		'''
		Scan a specific module for integrity checks (eg: hooks) using passive binay image technique.
		@Param pid - process id (int type)
		@Param modulename - name of the module (eg: kernel32) (str type)
		
		'''
		self.dbg.pid = pid
		print "Scanning module: %s in process: %d" % (modulename,pid)
		# walk thorugh the loaded modules
		for module in self.dbg.iterate_modules():
			name  = module.szExePath
			name = name.lower()
			modulename = modulename.lower()
			# get the requested module
			if re.search(modulename,name):
				try:
					# map module manually
					module_map = self._mapmodule(name)
					# Get base address of the module from memory (defeat ASLR)
					mem_base_addr = module.modBaseAddr
					size = self.pe.OPTIONAL_HEADER.SizeOfImage
					if hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"):
						# Get exported APIs
						for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
							p_addr = module_map + entry.address
							a_addr = mem_base_addr + entry.address
							# Look for the change at the API addresses.
							if self._checkchange(pid,p_addr,a_addr):
								print "Address: 0x%x API: %s DLL: %s" % (a_addr,entry.name,name)
				except Exception, why:
					#print "Error occured at module %s why: %s" % (modulename,why)
					pass
				# free passive binary image memory allocation	
				kernel32.VirtualFree(module_map,size,win32con.MEM_RELEASE)
				self.UnLoadPE()
		return
		
	def ScanPidForMod(self,pid):
		'''
		Scan process modules for integrity checks (eg: hooks) using passive image referencing.
		'''
		self.dbg.pid = pid
		print "Scanning process: %d" % pid
		# Interate through loaded modules
		for module in self.dbg.iterate_modules():
			try:
				print
				modulename = module.szExePath
				# map the module manually for passive refrencing
				module_map = self._mapmodule(modulename)
				# Get base address of the module from memory (defeat ASLR)
				mem_base_addr = module.modBaseAddr
				size = self.pe.OPTIONAL_HEADER.SizeOfImage
				if hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"):
					# Get exported APIs
					for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
						p_addr = module_map + entry.address
						a_addr = mem_base_addr + entry.address
						# Look for the change at the API addresses.
						if self._checkchange(pid,p_addr,a_addr):
							print "Address: 0x%x API: %s DLL: %s" % (a_addr,entry.name,modulename)
			except Exception, why:
				#print "Error occured at module %s why: %s" % (modulename,why)
				pass
			kernel32.VirtualFree(module_map,size,win32con.MEM_RELEASE)
			self.UnLoadPE()
				
		return
	
	def ScanRamForMod(self,modulename):
		'''
		Scan the entire RAM for integrity checks for the module.
		@Param modulename - name of the module (eg: kernel32) (str type)
		'''
		# get running process list
		plist = self.ShowProcesses()
		for entry in plist:
			pid = entry[0]
			if pid:
				self.ScanModInPid(pid,modulename)
		return			
	# Volatality functions
	
	def VolLoad(self,filename):
		'''
		@Param filename - full path of the image with "\\" seperation eg: c:\\test\\vmem.img"
		'''
		# Do some fix!!
		filename = filename.replace(":","|")
		filename = filename.replace("\\","/")
		config.LOCATION = "file:///" + filename
		print config.LOCATION
		return

	def VolCommand(self,command):
		'''
		Freely call voltality commands/plugins
		'''
		command = " " + command
		# Call our modified function
		volmain(command)
		return
	

def main():
	banner = "PyMal - Python Interactive Shell for Malware Analysis.\nUse Object \"pm\" to access the malware analysis related functions!\nAuthor: Amit Malik\nhttp://www.securityxploded.com\n"
	pm = PyMal()
	class pymalcomplete(rlcompleter.Completer):
		# Code segment from scapy - It is neat and mature
		def attr_matches(self, text):
			m = re.match(r"(\w+(\.\w+)*)\.(\w*)", text)
			if not m:
				return
			expr, attr = m.group(1, 3)
			try:
				object = eval(expr)
			except:
				object = eval(expr, session)
			words = dir(object)
			if hasattr(pm,"__class__" ):
				words = words + rlcompleter.get_class_members(pm.__class__)
			matches = []
			n = len(attr)
			for word in words:
				if word[:n] == attr:
					matches.append("%s.%s" % (expr, word))
			return matches
	readline.set_completer(pymalcomplete().complete)
	readline.parse_and_bind("C-o: operate-and-get-next")
	readline.parse_and_bind('tab: complete')
	code.interact(banner=banner,local = locals())
	
if __name__ == '__main__':
    #config.set_usage(usage = "Volatility - A memory forensics analysis platform.")
    config.add_help_hook(list_plugins)
    try:
        main()
    except Exception, ex:
        if config.DEBUG:
            debug.post_mortem()
        else:
            raise
    except KeyboardInterrupt:
        print "Interrupted"
		
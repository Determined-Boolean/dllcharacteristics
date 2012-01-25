 #!/usr/bin/env ruby
require 'optparse'
require 'find'

class BinarySecurityDetection
	def initialize()
		@dir = "C:\\"
		@dllCharacteristicsValue = ""
		@store = []
		@filetype = "ALL"
		@restrictedFiletypes = ["fon"]
		@ran = false
	end
	
	def recurse()
		puts "start"
		Find.find(@dir) do |fl|
			if (loadDLLCharacteristicsValue(fl))
				if (!setStore(fl))
					puts "dll characteristics for " + fl + " are not valid. This could be a parsing error. Check file manually"
				end
			else
				next
			end
		end
	end
	
	def readFile()
		if (!loadDLLCharacteristicsValue(@dir))
			puts @dir + " is not a file"
		end
	end
	
	def loadDLLCharacteristicsValue(fl)
		begin
			open(fl, "r") do |f|
				f.seek 0
				detectPE = f.read 2
				if (detectPE == "MZ")
					f.seek 60
					s = f.read 4
					offset = s.unpack('h4')[0].reverse.hex
					f.seek offset + 94
					@dllCharacteristicsValue = f.read(2).unpack('h*')[0].reverse
				else
					return false
				end
			end
		rescue
			return false
		end
		return true
	end
	
	def setStore(fl)
		if !checkFileType(fl)
			return true
		end
		storeVal = {
			:filename				=> fl, 
			:dllchars 				=> @dllCharacteristicsValue,
			:DYNAMIC_BASE			=> false,
			:FORCE_INTEGRITY		=> false,
			:NX_COMPAT				=> false,
			:NO_ISOLATION			=> false,
			:NO_SEH					=> false,
			:NO_BIND				=> false,
			:WDM_DRIVER				=> false,
			:TERMINAL_SERVER_AWARE	=> false
		}
		dllC = @dllCharacteristicsValue.hex
		
		if dllC > 0
			if dllC >= 32768
				storeVal[:TERMINAL_SERVER_AWARE] = true
				dllC -= 32768
			end
			if dllC >= 8192
				storeVal[:WDM_DRIVER] = true
				dllC -= 8192 
			end
			if dllC == 2048 or dllC > 2080
				storeVal[:NO_BIND] = true
				dllC -= 2048
			end
			if dllC == 1024 or dllC > 1056
				storeVal[:NO_SEH] = true
				dllC -= 1024
			end
			if dllC == 512 or dllC > 544
				storeVal[:NO_ISOLATION] = true
				dllC -= 512
			end
			if dllC == 256 or dllC > 288
				storeVal[:NX_COMPAT] = true
				dllC -= 256
			end
			if dllC >= 128
				storeVal[:FORCE_INTEGRITY] = true
				dllC -= 128
			end
			if dllC == 64
				storeVal[:DYNAMIC_BASE] = true
				dllC -= 64
			end
			if dllC != 0
				return false
			end
		else
			if @dllCharacteristicsValue != "0000"
				return false
			end
		end
		
		@store.push(storeVal)
		return true
	end
	
	def checkFileType(fl)
		@restrictedFiletypes.each do |rft|
			if fl =~ /#{rft}$/ then return false end
		end
		if @filetype =~ /^all/i then return true end
		@filetype.each do |ft|
			if fl =~ /#{ft}$/ then return true end
		end
		return false
	end
	
	def getDirectory()
		return @dir
	end
	
	def setDirectory(dir)
		if File.directory?(dir) or File.file?(dir)
			@dir = dir
			return true
		end
		return false
	end
	
	def setFiletype(filetype)
		@filetype = filetype.split(",")
	end
	
	def getSettings()
		settings = {
			:directory => @dir,
			:ran       => @ran,
			:filetype  => @filetype
		}
		return settings
	end
	
	def setRan() 
		@ran = true
	end
	
	def displayStoredValues(value)
		if !@ran then puts "Program needs to run first, type run"; return 0 end
		
		@store.each do |item|
			if !item[value]
				puts  item[:dllchars] + " filename: " + item[:filename]
			end
		end
	end
	
	def getNoASLR()
		displayStoredValues(:DYNAMIC_BASE)
	end
	
	def getNoDEP()
		displayStoredValues(:NX_COMPAT)
	end
	
	def getNoSEH()
		displayStoredValues(:NO_SEH)
	end
		
	def getForceIntegrity()
		displayStoredValues(:NO_SEH)
	end
	
	def noIsolation()
		displayStoredValues(:NO_ISOLATION)
	end
	
	def noBind()
		displayStoredValues(:NO_BIND)
	end
	
	def wdmDriver()
		displayStoredValues(:WDM_DRIVER)
	end
	
	def terminalServerAware()
		displayStoredValues(:TERMINAL_SERVER_AWARE)
	end
	
	def dllCharacteristicsSearch(dllchar)
		if !@ran then puts "Program needs to run first, type run"; return 0 end
		
		@store.each do |item|
			if item[:dllchars] == dllchar
				puts  item[:dllchars] + " filename: " + item[:filename]
			end
		end
	end
end

puts "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
puts "                                                       "
puts "             DLLCharacteristics Started                "
puts "                                                       "
puts "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
puts "start with  -h for help"
puts "\n"
b = BinarySecurityDetection.new()

while true
	begin  
	print b.getDirectory + ">"
	val = gets()
	case val
		when /^set/
			case val
				when /^set filetype\s.*/i
					filetype = val.gsub(/^set filetype\s/i, "").chop
					b.setFiletype(filetype)
				when /^set -h.*|^set help.*|^set -help.*/i
					puts "\tset filetype dll,exe,sys => set type of files you are interested in"
					puts "\n"
				else 
					puts "\tinvalid set command, try set -h"
			end
		when /^cd/i
			dir = val.gsub(/^cd\s/i, "").chop
			if (!b.setDirectory(dir))
				puts "\tinvalid directory or file path"
			end
		when /^run/i
			if b.getDirectory == "" or b.getDirectory == ".."
				puts "\tFile path is not set, cd to the path you want to scan"
			elsif File.file?(b.getDirectory)
				puts "Starting Scan on File"
				b.readFile()
				b.setRan() 
			else
				puts "Starting Scan on Directories"
				b.recurse
				b.setRan() 
			end
		when /^help|^-help\s|^-h/i
			puts "\tOptions"
			puts "\t set -h => set values"
			puts "\t show -h => request results"
			puts "\t cd => set the directory you want to scan"
			puts "\t run => start scan"
			puts "\t exit => exit application"
		when /^exit/i
			break
			exit
		when /^show/i
			case val
				when /^show settings.*/i
					settings = b.getSettings()
					puts "Directory: " + settings[:directory]
					puts "Ran? : " + settings[:ran].to_s
					if settings[:filetype] == nil
						puts "Filetypes : ALL"
					else 
						puts "Filetypes : " + settings[:filetype].join(",").to_s
					end
				when /^show directory.*/i
					puts b.getDirectory()
				when /^show noaslr.*/i
					b.getNoASLR()
				when /^show nodep.*/i
					b.getNoDEP()
				when /^show noseh.*/i
					b.getNoSEH()
				when /^show forceIntegrity.*/i
					b.getForceIntegrity
				when /^show noIsolation.*/i	
					b.noIsolation
				when /^show nobind.*/i
					b.noBind
				when /^show wdmdriver/i
					b.wdmDriver
				when /^show terminalserveraware.*/i
					b.terminalServerAware
				when /^show [0-9]{4}[\s].*/i
					dllchar = val.gsub(/^show\s/, "").chomp
					b.dllCharacteristicsSearch(dllchar)
				when /^show -h.*|^show help.*|^show -help.*/i
					puts "\tOptions"
					puts "\t show settings => current settings"
					puts "\t show directory => directory or file to scan"
					puts "\t show noaslr => show files stored with aslr disabled"
					puts "\t show nodep => show files stored with dep disabled"
					puts "\t show noseh => show files stored with no SEH support"
					puts "\t show forceIntegrity => show files stored with code integrity checks forced"
					puts "\t show noIsolation => show files stored that are isolation aware"
					puts "\t show nobind => show files stored that have bind disabled"
					puts "\t show wdmdriver => show stored files that are wdm drivers"
					puts "\t show terminalserveraware => show stored files that are terminal server aware"
					puts "\t show [0-9a-f]{4} => show any file with this dll characteristics value"
					puts "\t show -h => this help screen"
					puts "\t reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx"
				else
					puts "\t invalid show value, try show -h"
			end
		else
			puts "invalid command"
	end
	rescue Exception => e
		print "\n\nProgram Halted"
		break
		exit
	end
end

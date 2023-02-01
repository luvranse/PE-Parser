#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <sstream>
#include "pe3264.h"
#include "pe_exception.h"

int main(int argc, const char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: sectons.exe pe_file" << std::endl;
		return 0;
	}

	std::ifstream pefile;
	pefile.open(argv[1], std::ios::in | std::ios::binary);
	if(!pefile.is_open())
	{
		std::cout << "Can't open file" << std::endl;
		return 0;
	}

	try
	{
		pe64 executable(pefile);
		if(executable.has_imports())
		{
			const IMAGE_IMPORT_DESCRIPTOR* import_descriptor_array = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(executable.section_data_from_rva(executable.directory_rva(IMAGE_DIRECTORY_ENTRY_IMPORT)));

			while(import_descriptor_array->Characteristics)
			{
				std::cout << "DLL Name: " << executable.section_data_from_rva(import_descriptor_array->Name) << std::endl;
				std::cout << "Import TimeDateStamp: 0x" << std::hex << import_descriptor_array->TimeDateStamp << std::endl;

				const DWORD* import_address_table = reinterpret_cast<const DWORD*>(executable.section_data_from_rva(import_descriptor_array->FirstThunk));
				const DWORD* import_lookup_table = import_descriptor_array->OriginalFirstThunk == 0 ? import_address_table : reinterpret_cast<const DWORD*>(executable.section_data_from_rva(import_descriptor_array->OriginalFirstThunk));

				DWORD address_table = import_descriptor_array->FirstThunk;

				std::string name;
				WORD hint;

				std::cout << std::endl << " hint | name/ordinal                |  address" << std::endl;

				if(import_lookup_table != 0 && import_address_table != 0)
				{
					while(true)
					{
						DWORD address = *import_address_table++;

						if(!address)
							break;

						DWORD lookup = *import_lookup_table++;

						if(IMAGE_SNAP_BY_ORDINAL32(lookup))
						{
							std::stringstream stream;
							stream << "#" << IMAGE_ORDINAL32(lookup);
							name = stream.str();
							hint = 0;
						}
						else
						{
							name = executable.section_data_from_rva(lookup + 2);
							hint = *reinterpret_cast<const WORD*>(executable.section_data_from_rva(lookup));
						}

						std::cout << std::dec << "[" << std::setfill('0') << std::setw(4) << hint << "]"
							<< " " << std::left << std::setfill(' ') << std::setw(30) << name
							<< ":0x" << std::hex << std::right << std::setfill('0') << std::setw(8) << address_table
							<< std::endl;

						address_table += 4;
					}
				}

				std::cout << "==========" << std::endl << std::endl;

				import_descriptor_array++;
			}
		}
	}
	catch(const pe_exception& e)
	{
		std::cout << "Exception: " << e.what() << std::endl;
	}

	return 0;
}

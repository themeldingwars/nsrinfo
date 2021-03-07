#define ZLIB_CONST
#include <zlib.h>
#include <zconf.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>

struct nsr
{
	unsigned int header_size;
	unsigned int protocol_version;
	unsigned int zone;
	std::string description;
	std::string date;
	std::string user;
	std::string version;
	std::string date2;

	void serialize() const
    {
		std::cout << "Header Size:      " << header_size << std::endl;
		std::cout << "Protocol Version: " << protocol_version << std::endl;
		std::cout << "Zone:             " << zone << std::endl;
		std::cout << "Description:      " << description << std::endl;
		std::cout << "Date:             " << date << std::endl;
		std::cout << "User:             " << user << std::endl;
		std::cout << "Firefall Version: " << version << std::endl;
		std::cout << "Date2:            " << date2 << std::endl;
	}
};

bool gzip_inflate(const std::string& compressed_bytes, std::stringstream& uncompressed_bytes)
{
	if (compressed_bytes.empty())
	{
		uncompressed_bytes.str(compressed_bytes);
		return true;
	}

	uncompressed_bytes.str("");

	std::vector<char> uncomp(compressed_bytes.size(), 0);

	z_stream strm;
	strm.next_in = reinterpret_cast<z_const Bytef*>(compressed_bytes.data());
	strm.avail_in = compressed_bytes.size();
	strm.total_out = 0;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;

	if (inflateInit2(&strm, (16 + MAX_WBITS)) != Z_OK)
	{
	    return false;
	}

    auto ret = Z_OK;

	while (ret == Z_OK)
	{
		// If the output buffer is too small
		if(strm.total_out >= uncomp.size())
			uncomp.resize((uncomp.size() * 3) / 2 + 1, 0);

		strm.next_out = reinterpret_cast<Bytef*>(uncomp.data() + strm.total_out);
		strm.avail_out = uncomp.size() - strm.total_out;

		// Inflate another chunk.
		ret = inflate(&strm, Z_SYNC_FLUSH);
	}

	if (inflateEnd(&strm) != Z_OK)
	{
	    return false;
	}

	for (std::size_t i = 0; i < strm.total_out; ++i)
	{
		uncompressed_bytes.put(uncomp[i]);
	}

	uncompressed_bytes.seekg(0);

	return true;
}

// Reads a file into memory
bool load_binary_file(const std::string& filename, std::string& contents)
{
	// Open the gzip file in binary mode
	std::fstream file(filename, std::ios::binary | std::ios::in);

	if (!file.is_open())
	{
	    return false;
	}

	contents.clear();

	// Read all the bytes in the file
	char buffer[1024] = {0};

	while (file.read(buffer, 1024))
	{
		contents.append(buffer, file.gcount());
	}

	return true;
}

std::ifstream::pos_type get_size(std::fstream& stream)
{
    const auto pos = stream.tellg();
    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    stream.seekg(pos);
    return size;
}

bool char_n_compare(const char* chr1, const char* chr2, const std::size_t count)
{
    auto cmp = true;

	for (std::size_t i = 0; i < count; ++i)
	{
	    cmp = cmp && (chr1[i] == chr2[i]);
	}

	return cmp;
}

inline void endian_swap(unsigned int& x)
{
	x = (x>>24) |
		((x<<8) & 0x00FF0000) |
	    ((x>>8) & 0x0000FF00) |
	    (x<<24);
}

void ignore_padding(std::stringstream& stream)
{
	char tmp = 0;

	while (tmp == 0)
	{
	    stream.read(&tmp, 1);
	}

	stream.seekg(stream.tellg() - 1ll);
}

int main(int argc, char* argv[])
{
	// Help text
	if (argc < 2 || (argc >= 2 && std::strncmp(argv[1], "--help", 6) == 0))
	{
		std::cout << "Usage: nsrinfo [OPTION] FILE" << std::endl;
		std::cout << std::endl;
		std::cout << "Arguments:" << std::endl;
		std::cout << " OPTION   An option to influence the application behavior." << std::endl;
		std::cout << " FILE     The NSR file to extract information from." << std::endl;
		std::cout << std::endl;
		std::cout << "Possible options:" << std::endl;
		std::cout << " --help   Show this text" << std::endl;
	}
	// Application
	else if (argc >= 2)
	{
		std::string filename;

		for (auto i = 1; i < argc; ++i)
		{
			// Option
			if (argv[i][0] != '-' || argv[i][1] != '-')
			{
				filename = argv[i];
			}
		}

		nsr file;
		std::string file_data;
		std::stringstream nsrfile;

		if (!load_binary_file(filename, file_data))
		{
			std::cerr << "Could not open the NSR file: " << filename << std::endl;
			return 1;
		}

		if (!gzip_inflate(file_data, nsrfile))
		{
			std::cerr << "Could not decompress the NSR file: " << filename << std::endl;
			return 1;
		}

		if (nsrfile.tellg() != -1 && !nsrfile.eof())
		{
			// NSRD & NSRI
			std::vector<char> data(4, 0);
			nsrfile.read(static_cast<char*>(data.data()), 4);
			if (!char_n_compare("NSRD", data.data(), 4))
			{
				std::cerr << "Unknown format" << std::endl;
				return 2;
			}
			nsrfile.seekg(4, std::ios::cur); // Ignore 4 bytes
			nsrfile.read(reinterpret_cast<char*>(&file.header_size), 4);
			nsrfile.seekg(16, std::ios::cur); // Ignore 16 bytes
			nsrfile.read(reinterpret_cast<char*>(&file.protocol_version), 4);
			nsrfile.seekg(file.header_size - 28, std::ios::cur); // Ignore the header - 28 bytes
			nsrfile.read(reinterpret_cast<char*>(&file.zone), 4);

			// Meta data
			std::getline(nsrfile, file.description, '\0');
			std::getline(nsrfile, file.date, '\0');
			nsrfile.seekg(36, std::ios::cur); // Ignore 36 bytes
			std::getline(nsrfile, file.user, '\0');
			nsrfile.seekg(18, std::ios::cur); // Ignore 18 bytes
			std::getline(nsrfile, file.version, '\0');
			nsrfile.seekg(28, std::ios::cur); // Ignore 28 bytes
			std::getline(nsrfile, file.date2, '\0');
			ignore_padding(nsrfile); // Ignore the 00 padding

			file.serialize();
		}

		char tmp[7] = {0};
		unsigned char start1[] = {0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
		unsigned char start2[] = {0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF};
		std::string name1;
		std::string name2;
	}
	else
	{
		std::cout << "Invalid number of arguments!" << std::endl;
		return -1;
	}

	return 0;
}
package ghidragb.utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class GameBoyHeaders
{
	/*
	 * Credits:
	 * - http://gbdev.gg8.se/wiki/articles/The_Cartridge_Header
	 */
	
	private short entrypoint = 0x100;
	private byte[] nintendo_logo;			/* 0x0104 - 0x0133 */
	private String title;					/* 0x0134 - 0x0143 */
	private short new_licence_code;			/* 0x0144 - 0x0145 */
	private byte sgb_flag;					/* 0x0146 */
	private byte cartridge_type;			/* 0x0147 */
	private int rom_size;					/* 0x0148 */
	private int ram_size;					/* 0x0149 */
	private byte destination_code;			/* 0x014A */
	private byte old_licence_code;			/* 0x014B */
	private byte mask_rom_version;			/* 0x014C */
	private byte header_checksum;			/* 0x014D */
	private short global_checksum;			/* 0x014E - 0x014F */
	
	public GameBoyHeaders(BinaryReader reader) throws IOException
	{
		this.nintendo_logo = reader.readByteArray(0x0104, 0x30);
		this.title = reader.readAsciiString(0x0134, 0x10);
		this.new_licence_code = reader.readShort(0x0144);
		this.sgb_flag = reader.readByte(0x0146);
		this.cartridge_type = reader.readByte(0x0147);
		this.rom_size = GameBoyHeadersUtils.calc_rom_size(reader.readByte(0x0148));
		this.ram_size = GameBoyHeadersUtils.calc_ram_size(reader.readByte(0x0149));
		this.destination_code = reader.readByte(0x014A);
		this.old_licence_code = reader.readByte(0x014B);
		this.mask_rom_version = reader.readByte(0x014C);
		this.header_checksum = reader.readByte(0x014D);
		this.global_checksum = reader.readShort(0x014E);
	}
	
	public static Structure getDataStructure()
	{
		Structure header_struct = new StructureDataType("header_item", 0);
		
		header_struct.add(StructConverter.VOID, 16*3, "nintendo_logo", null);
		header_struct.add(StructConverter.STRING, 16, "title", null);
		header_struct.add(StructConverter.WORD, 2, "new_licence_code", null);
		header_struct.add(StructConverter.BYTE, 1, "sgb_flag", null);
		header_struct.add(StructConverter.BYTE, 1, "cartridge_type", null);
		header_struct.add(StructConverter.BYTE, 1, "rom_size", null);
		header_struct.add(StructConverter.BYTE, 1, "ram_size", null);
		header_struct.add(StructConverter.BYTE, 1, "destination_code", null);
		header_struct.add(StructConverter.BYTE, 1, "old_licence_code", null);
		header_struct.add(StructConverter.BYTE, 1, "mask_rom_version", null);
		header_struct.add(StructConverter.BYTE, 1, "header_checksum", null);
		header_struct.add(StructConverter.WORD, 2, "global_checksum", null);
		
		return header_struct;
	}
	
	public boolean check_header()
	{
		/* Thx to Java who don't support unsigned numbers... */
		byte[] valid_header = new byte[] {
			(byte) 0xCE, (byte) 0xED, 0x66, 0x66, (byte) 0xCC, 0x0D, 0x00, 0x0B,
			0x03, 0x73, 0x00, (byte) 0x83, 0x00, 0x0C, 0x00, 0x0D,
			0x00, 0x08, 0x11, 0x1F, (byte) 0x88, (byte) 0x89, 0x00, 0x0E,
			(byte) 0xDC, (byte) 0xCC, 0x6E, (byte) 0xE6, (byte) 0xDD, (byte) 0xDD, (byte) 0xD9, (byte) 0x99,
			(byte) 0xBB, (byte) 0xBB, 0x67, 0x63, 0x6E, 0x0E, (byte) 0xEC, (byte) 0xCC,
			(byte) 0xDD, (byte) 0xDC, (byte) 0x99, (byte) 0x9F, (byte) 0xBB, (byte) 0xB9, 0x33, 0x3E
		};

		return Arrays.equals(this.nintendo_logo, valid_header);
	}
	
	public short getEntrypoint() {
		return entrypoint;
	}

	public byte[] getNintendo_logo() {
		return nintendo_logo;
	}

	public String getTitle() {
		return title;
	}

	public short getNew_licence_code() {
		return new_licence_code;
	}

	public byte getSgb_flag() {
		return sgb_flag;
	}

	public byte getCartridge_type() {
		return cartridge_type;
	}

	public int getRom_size() {
		return rom_size;
	}

	public int getRam_size() {
		return ram_size;
	}

	public byte getDestination_code() {
		return destination_code;
	}

	public byte getOld_licence_code() {
		return old_licence_code;
	}

	public byte getMask_rom_version() {
		return mask_rom_version;
	}

	public byte getHeader_checksum() {
		return header_checksum;
	}

	public short getGlobal_checksum() {
		return global_checksum;
	}
}

class GameBoyHeadersUtils
{
	public static int calc_ram_size(byte type)
	{
		Map<Integer, Integer> dict = new HashMap<Integer, Integer>() {{
			put(0x00, 0);
			put(0x01, 2 * 1024);
			put(0x02, 8 * 1024);
			put(0x03, 32 * 1024);
			put(0x04, 128 * 1024);
			put(0x05,  64 * 1024);
		}};
		
		return dict.getOrDefault(type, 0);
	}
	
	public static int calc_rom_size(byte type)
	{
		Map<Integer, Integer> dict = new HashMap<Integer, Integer>() {{
			put(0x00, 32 * 1024);
			put(0x01, 64 * 1024);
			put(0x02, 128 * 1024);
			put(0x03, 256 * 1024);
			put(0x04, 512 * 1024);
			put(0x05, 1 * 1024 * 1024);
			put(0x06, 2 * 1024 * 1024);
			put(0x07, 4 * 1024 * 1024);
			put(0x08, 8 * 1024 * 1024);
			put(0x52, (int) (1.1 * 1024 * 1024));
			put(0x53, (int) (1.2 * 1024 * 1024));
			put(0x54, (int) (1.5 * 1024 * 1024));
		}};
		
		return dict.getOrDefault(type, 0);
	}
}
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidragb;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidragb.utils.GameBoyHeaders;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraGBLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "GameBoy";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		GameBoyHeaders gb_headers;
		
		try
		{
			gb_headers = new GameBoyHeaders(reader);
		}
		catch (IOException e)
		{
			System.out.println(e.getMessage());
			return loadSpecs;
		}
		
		if (!gb_headers.check_header())
			return loadSpecs;

		List<QueryResult> queries = QueryOpinionService.query(getName(), "1", null);
		
		for (QueryResult result : queries)
			loadSpecs.add(new LoadSpec(this, 0, result));		

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException
	{		
		monitor.setMessage("GameBoy Loader: Start loading");
		
		MemoryBlockUtil mbu = new MemoryBlockUtil(program, handler);

		try
		{
			createHeaderSection(program, mbu, provider, monitor);
			createEntrypointSection(program, mbu, provider, monitor);
		}
		catch (CodeUnitInsertionException | AddressOverflowException | InvalidInputException
				| OverlappingFunctionException e)
		{
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
	
	private void createHeaderSection(Program program, MemoryBlockUtil mbu, ByteProvider provider,
			TaskMonitor monitor) throws AddressOverflowException, IOException, CodeUnitInsertionException
	{
		Structure header_struct = GameBoyHeaders.getDataStructure();
		Address begin_header = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0104);

		mbu.createInitializedBlock(".header", begin_header, provider.getInputStream(0x0104), 0x4C,
				"The ROM header", "ROM Header", true, true, true, monitor);

		DataUtilities.createData(program, begin_header, header_struct, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}
	
	private void createEntrypointSection(Program program, MemoryBlockUtil mbu, ByteProvider provider,
			TaskMonitor monitor) throws AddressOverflowException, IOException, InvalidInputException,
			OverlappingFunctionException
	{
		AddressSpace as = program.getAddressFactory().getDefaultAddressSpace();
		Address begin_entrypoint = as.getAddress(0x0100);
		Address end_entrypoint = as.getAddress(0x0103);
		AddressSet body = new AddressSet(begin_entrypoint, end_entrypoint);

		mbu.createInitializedBlock(".entrypoint", begin_entrypoint, provider.getInputStream(0x0100), 0x04,
				"The ROM Entrypoint", "ROM Entrypoint", true, true, true, monitor);

		program.getFunctionManager().createFunction("entrypoint", begin_entrypoint, body, SourceType.ANALYSIS);
	}
}

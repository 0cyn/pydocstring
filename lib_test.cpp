#include <string>
#include <iostream>
#include "library.h"
/*
>>> def dump_docstrings(module):
...     i = 0
...     out = "std::vector<std::string> tests = {"
...     for name, obj in inspect.getmembers(module):
...         if inspect.isfunction(obj) or inspect.isclass(obj) or inspect.ismodule(obj):
...             if obj.__doc__ is not None:
...                 print(f"std::string test_{i} = R\"({obj.__doc__})\"")
...                 out += f"test_{i}, "
...                 i+=1
...     print(out + "}")
... 
... 
>>> dump_docstrings(binaryninja)
*/
std::string test_0 = R"(An enumeration.)";
std::string test_1 = R"(ActiveAnalysisInfo(func: '_function.Function', analysis_time: int, update_count: int, submit_count: int))";
std::string test_2 = R"(
	:class:`Activity`
	)";
std::string test_3 = R"(
	``AddressField`` prompts the user for an address. By passing the optional view and current_address parameters 	offsets can be used instead of just an address. The result is stored as in int in self.result.

	.. note:: This API currently functions differently on the command-line, as the view and current_address are 	disregarded. Additionally where as in the UI the result defaults to hexadecimal on the command-line 0x must be 	specified.

	)";
std::string test_4 = R"(AddressRange(start: int, end: int))";
std::string test_5 = R"(
	The purpose of this class is to generate IL functions IL function in the background
	improving the performance of iterating MediumLevelIL and HighLevelILFunctions.

	Using this class or the associated helper methods BinaryView.mlil_functions / BinaryView.hlil_functions
	can improve the performance of ILFunction iteration significantly

	The prefetch_limit property is configurable and should be modified based upon your machines hardware and RAM limitations.

	.. warning:: Setting the prefetch_limit excessively high can result in high memory utilization.

	:Example:
		>>> import timeit
		>>> len(bv.functions)
		4817
		>>> # Calculate the average time to generate hlil for all functions withing 'bv':
		>>> timeit.timeit(lambda:[f.hlil for f in bv.functions], number=1)
		21.761621682000168
		>>> t1 = _
		>>> # Now try again with the advanced analysis iterator
		>>> timeit.timeit(lambda:[f for f in bv.hlil_functions(128)], number=1)
		6.3147709989998475
		>>> t1/_
		3.4461458199270947
		>>> # This particular binary can iterate hlil functions 3.4x faster
		>>> # If you don't need IL then its still much faster to just use `bv.functions`
		>>> timeit.timeit(lambda:[f for f in bv.functions], number=1)
		0.02230275600004461
	)";
std::string test_6 = R"(AliasedVariableInstruction())";
std::string test_7 = R"(
	The ``AnalysisCompletionEvent`` object provides an asynchronous mechanism for receiving
	callbacks when analysis is complete. The callback runs once. A completion event must be added
	for each new analysis in order to be notified of each analysis completion.  The
	AnalysisCompletionEvent class takes responsibility for keeping track of the object's lifetime.

	:Example:
		>>> def on_complete(self):
		...     print("Analysis Complete", self._view)
		...
		>>> evt = AnalysisCompletionEvent(bv, on_complete)
		>>>
	)";
std::string test_8 = R"(
	The ``AnalysisContext`` object is used to represent the current state of analysis for a given function.
	It allows direct modification of IL and other analysis information.
	)";
std::string test_9 = R"(AnalysisInfo(state: binaryninja.enums.AnalysisState, analysis_time: int, active_info: List[binaryninja.binaryview.ActiveAnalysisInfo]))";
std::string test_10 = R"(An enumeration.)";
std::string test_11 = R"(AnalysisProgress(state: binaryninja.enums.AnalysisState, count: int, total: int))";
std::string test_12 = R"(An enumeration.)";
std::string test_13 = R"(An enumeration.)";
std::string test_14 = R"(An enumeration.)";
std::string test_15 = R"(ArchAndAddr(arch: 'architecture.Architecture', addr: int))";
std::string test_16 = R"(
	``class Architecture`` is the parent class for all CPU architectures. Subclasses of Architecture implement assembly,
	disassembly, IL lifting, and patching.

	``class Architecture`` has a metaclass with the additional methods ``register``, and supports
	iteration::

		>>> #List the architectures
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: thumb2>, <arch: armv7eb>, <arch: thumb2eb>, <arch: mipsel32>, <arch: mips32>, <arch: ppc>, <arch: ppc64>, <arch: ppc_le>, <arch: ppc64_le>, <arch: x86_16>, <arch: x86>, <arch: x86_64>]
		>>> #Register a new Architecture
		>>> class MyArch(Architecture):
		...  name = "MyArch"
		...
		>>> MyArch.register()
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: thumb2>, <arch: armv7eb>, <arch: thumb2eb>, <arch: mipsel32>, <arch: mips32>, <arch: ppc>, <arch: ppc64>, <arch: ppc_le>, <arch: ppc64_le>, <arch: x86_16>, <arch: x86>, <arch: x86_64>, <arch: MyArch>]
		>>>

	For the purposes of this documentation the variable ``arch`` will be used in the following context ::

		>>> from binaryninja import *
		>>> arch = Architecture['x86']

	.. note:: The `max_instr_length` property of an architecture is not necessarily representative of the maximum instruction size of the associated CPU architecture. Rather, it represents the maximum size of a potential instruction that the architecture plugin can handle. So for example, the value for x86 is 16 despite the lagest valid instruction being only 15 bytes long, and the value for mips32 is currently 8 because multiple instrutions are decoded looking for delay slots so they can be reordered.

	)";
std::string test_17 = R"(Arithmetic())";
std::string test_18 = R"(BaseILInstruction())";
std::string test_19 = R"(BaseStructure(type: Union[ForwardRef('NamedTypeReferenceType'), ForwardRef('StructureType')], offset: int, width: int = 0))";
std::string test_20 = R"(
	The ``BasicBlock`` object is returned during analysis and should not be directly instantiated.
	)";
std::string test_21 = R"(BasicBlockEdge(type: binaryninja.enums.BranchType, source: 'BasicBlock', target: 'BasicBlock', back_edge: bool, fall_through: bool))";
std::string test_22 = R"(BasicTypeParserResult(types: Dict[ForwardRef('types.QualifiedName'), ForwardRef('types.Type')], variables: Dict[ForwardRef('types.QualifiedName'), ForwardRef('types.Type')], functions: Dict[ForwardRef('types.QualifiedName'), ForwardRef('types.Type')]))";
std::string test_23 = R"(
	``class BinaryDataNotification`` provides an interface for receiving event notifications. Usage requires inheriting
	from this interface, overriding the relevant event handlers, and registering the `BinaryDataNotification` instance
	with a `BinaryView` using the `register_notification` method.

	By default, a `BinaryDataNotification` instance receives notifications for all available notification types. It
	is recommended for users of this interface to initialize the `BinaryDataNotification` base class with with specific
	callbacks of interest by passing the appropriate `NotificationType` flags into the `__init__` constructor.

	Handlers provided by the user should aim to limit the amount of processing within the callback. The
	callback context holds a global lock, preventing other threads from making progress during the callback phase.
	While most of the API can be used safely during this time, care must be taken when issuing a call that can block,
	as waiting for a thread requiring the global lock can result in deadlock.

	The `NotificationBarrier` is a special `NotificationType` that is disabled by default. To enable it, the
	`NotificationBarrier` flag must be passed to `__init__`. This notification is designed to facilitate efficient
	batch processing of other notification types. The idea is to collect other notifications of interest into a cache,
	which can be very efficient as it doesn't require additional locks. After some time, the core generates a
	`NotificationBarrier` event, providing a safe context to move the cache for processing by a different thread.

	To control the time of the next `NotificationBarrier` event, return the desired number of milliseconds until
	the next event from the `NotificationBarrier` callback. Returning zero quiesces future `NotificationBarrier`
	events. If the `NotificationBarrier` is quiesced, the reception of a new callback of interest automatically
	generates a new `NotificationBarrier` call after that notification is delivered. This mechanism effectively
	allows throttling and quiescing when necessary.

	.. note:: Note that the core generates a `NotificationBarrier` as part of the `BinaryDataNotification` registration 	process. Registering the same `BinaryDataNotification` instance again results in a gratuitous `NotificationBarrier` 	event, which can be useful in situations requiring a safe context for processing due to some other asynchronous 	event (e.g., user interaction).

	:Example:

	>>> class NotifyTest(binaryninja.BinaryDataNotification):
	... 	def __init__(self):
	... 		super(NotifyTest, self).__init__(binaryninja.NotificationType.NotificationBarrier | binaryninja.NotificationType.FunctionLifetime | binaryninja.NotificationType.FunctionUpdated)
	... 		self.received_event = False
	... 	def notification_barrier(self, view: 'BinaryView') -> int:
	... 		has_events = self.received_event
	... 		self.received_event = False
	... 		log_info("notification_barrier")
	... 		if has_events:
	... 			return 250
	... 		else:
	... 			return 0
	... 	def function_added(self, view: 'BinaryView', func: '_function.Function') -> None:
	... 		self.received_event = True
	... 		log_info("function_added")
	... 	def function_removed(self, view: 'BinaryView', func: '_function.Function') -> None:
	... 		self.received_event = True
	... 		log_info("function_removed")
	... 	def function_updated(self, view: 'BinaryView', func: '_function.Function') -> None:
	... 		self.received_event = True
	... 		log_info("function_updated")
	...
	>>>
	>>> bv.register_notification(NotifyTest())
	>>>
	)";
std::string test_24 = R"(BinaryOperation())";
std::string test_25 = R"(
	``class BinaryReader`` is a convenience class for reading binary data.

	BinaryReader can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> hex(br.read32())
		'0xfeedfacfL'
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> br = BinaryReader(bv, Endianness.BigEndian)
		>>> hex(br.read32())
		'0xcffaedfeL'
		>>>
	)";
std::string test_26 = R"(
	``class BinaryView`` implements a view on binary data, and presents a queryable interface of a binary file. One key
	job of BinaryView is file format parsing which allows Binary Ninja to read, write, insert, remove portions
	of the file given a virtual address. For the purposes of this documentation we define a virtual address as the
	memory address that the various pieces of the physical file will be loaded at.

	A binary file does not have to have just one BinaryView, thus much of the interface to manipulate disassembly exists
	within or is accessed through a BinaryView. All files are guaranteed to have at least the ``Raw`` BinaryView. The
	``Raw`` BinaryView is simply a hex editor, but is helpful for manipulating binary files via their absolute addresses.

	BinaryViews are plugins and thus registered with Binary Ninja at startup, and thus should **never** be instantiated
	directly as this is already done. The list of available BinaryViews can be seen in the BinaryViewType class which
	provides an iterator and map of the various installed BinaryViews::

		>>> list(BinaryViewType)
		[<view type: 'Raw'>, <view type: 'ELF'>, <view type: 'Mach-O'>, <view type: 'PE'>]
		>>> BinaryViewType['ELF']
		<view type: 'ELF'>

	To open a file with a given BinaryView the following code is recommended:

		>>> with load("/bin/ls") as bv:
		...   bv
		<BinaryView: '/bin/ls', start 0x100000000, len 0x142c8>

	`By convention in the rest of this document we will use bv to mean an open and, analyzed, BinaryView of an executable file.`
	When a BinaryView is open on an executable view analysis is automatically run unless specific named parameters are used
	to disable updates. If such a parameter is used, updates can be triggered using the :py:func:`update_analysis_and_wait` method
	which disassembles the executable and returns when all disassembly and analysis is complete::

		>>> bv.update_analysis_and_wait()
		>>>

	Since BinaryNinja's analysis is multi-threaded (depending on version) this can also be done in the background
	by using the :py:func:`update_analysis` method instead.

	By standard python convention methods which start with '_' should be considered private and should not
	be called externally. Additionally, methods which begin with ``perform_`` should not be called directly
	either and are used explicitly for subclassing a BinaryView.

	.. note:: An important note on the ``*_user_*()`` methods. Binary Ninja makes a distinction between edits 	performed by the user and actions performed by auto analysis.  Auto analysis actions that can quickly be recalculated 	are not saved to the database. Auto analysis actions that take a long time and all user edits are stored in the 	database (e.g. :py:func:`remove_user_function` rather than :py:func:`remove_function`). Thus use ``_user_`` methods if saving 	to the database is desired.
	)";
std::string test_27 = R"(
	The ``BinaryViewEvent`` object provides a mechanism for receiving callbacks	when a BinaryView
	is Finalized or the initial analysis is finished. The BinaryView finalized callbacks run before the
	initial analysis starts. The callbacks run one-after-another in the same order as they get registered.
	It is a good place to modify the BinaryView to add extra information to it.

	For newly opened binaries, the initial analysis completion callbacks run after the initial analysis,
	as well as linear sweep	and signature matcher (if they are configured to run), completed. For loading
	old databases, the callbacks run after the database is loaded, as well as any automatic analysis
	update finishes.

	The callback function receives a BinaryView as its parameter. It is possible to call
	BinaryView.add_analysis_completion_event() on it to set up other callbacks for analysis completion.

	:Example:
		>>> def callback(bv):
		... 	print('start: 0x%x' % bv.start)
		...
		>>> BinaryViewType.add_binaryview_finalized_event(callback)
	)";
std::string test_28 = R"(An enumeration.)";
std::string test_29 = R"(
	The ``BinaryViewType`` object is used internally and should not be directly instantiated.
	)";
std::string test_30 = R"(
	``class BinaryWriter`` is a convenience class for writing binary data.

	BinaryWriter can be instantiated as follows and the rest of the document will start from this context ::

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> br = BinaryReader(bv)
		>>> br.offset
		4294967296
		>>> bw = BinaryWriter(bv)
		>>>

	Or using the optional endian parameter ::

		>>> from binaryninja import *
		>>> bv = load("/bin/ls")
		>>> br = BinaryReader(bv, Endianness.BigEndian)
		>>> bw = BinaryWriter(bv, Endianness.BigEndian)
		>>>
	)";
std::string test_31 = R"(BoolWithConfidence(value: bool, confidence: int = 255))";
std::string test_32 = R"(An enumeration.)";
std::string test_33 = R"(Call())";
std::string test_34 = R"(An enumeration.)";
std::string test_35 = R"(Carry())";
std::string test_36 = R"(
	``ChoiceField`` prompts the user to choose from the list of strings provided in ``choices``. Result is stored 	in self.result as an index in to the choices array.

	:attr str prompt: prompt to be presented to the user
	:attr list(str) choices: list of choices to choose from
	)";
std::string test_37 = R"(Comparison())";
std::string test_38 = R"(
    Components are objects that can contain Functions and other Components.

    They can be queried for information about the functions contained within them.

    Components have a Guid, which persistent across saves and loads of the database, and should be
    used for retrieving components when such is required and a reference to the Component cannot be held.

    )";
std::string test_39 = R"(Constant())";
std::string test_40 = R"(ConstantData(value: int, offset: int, type: binaryninja.enums.RegisterValueType = <RegisterValueType.UndeterminedValue: 0>, confidence: int = 255, size: int = 0, function: '_function.Function' = None))";
std::string test_41 = R"(ConstantDataRegisterValue(value: int, offset: int, type: binaryninja.enums.RegisterValueType = <RegisterValueType.UndeterminedValue: 0>, confidence: int = 255, size: int = 0))";
std::string test_42 = R"(ConstantPointerRegisterValue(value: int, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.ConstantPointerValue: 3>, confidence: int = 255, size: int = 0))";
std::string test_43 = R"(ConstantReference(value: int, size: int, pointer: bool, intermediate: bool))";
std::string test_44 = R"(ConstantRegisterValue(value: int, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.ConstantValue: 2>, confidence: int = 255, size: int = 0))";
std::string test_45 = R"(ControlFlow())";
std::string test_46 = R"(CoreDataVariable(_address: int, _type: '_types.Type', _auto_discovered: bool))";
std::string test_47 = R"(CoreHighLevelILInstruction(operation: binaryninja.enums.HighLevelILOperation, attributes: int, source_operand: int, size: int, operands: Tuple[binaryninja.highlevelil.ExpressionIndex, binaryninja.highlevelil.ExpressionIndex, binaryninja.highlevelil.ExpressionIndex, binaryninja.highlevelil.ExpressionIndex, binaryninja.highlevelil.ExpressionIndex], address: int, parent: binaryninja.highlevelil.ExpressionIndex))";
std::string test_48 = R"(CoreLowLevelILInstruction(operation: binaryninja.enums.LowLevelILOperation, attributes: int, size: int, flags: int, source_operand: binaryninja.lowlevelil.ExpressionIndex, operands: Tuple[binaryninja.lowlevelil.ExpressionIndex, binaryninja.lowlevelil.ExpressionIndex, binaryninja.lowlevelil.ExpressionIndex, binaryninja.lowlevelil.ExpressionIndex], address: int))";
std::string test_49 = R"(CoreMediumLevelILInstruction(operation: binaryninja.enums.MediumLevelILOperation, attributes: int, source_operand: int, size: int, operands: Tuple[binaryninja.mediumlevelil.ExpressionIndex, binaryninja.mediumlevelil.ExpressionIndex, binaryninja.mediumlevelil.ExpressionIndex, binaryninja.mediumlevelil.ExpressionIndex, binaryninja.mediumlevelil.ExpressionIndex], address: int))";
std::string test_50 = R"(CoreVariable(_source_type: int, index: int, storage: int))";
std::string test_51 = R"(CoreVersionInfo(major: int, minor: int, build: int, channel: str))";
std::string test_52 = R"(An enumeration.)";
std::string test_53 = R"(
	DataRenderer objects tell the Linear View how to render specific types.

	The `perform_is_valid_for_data` method returns a boolean to indicate if your derived class
	is able to render the type, given the `addr` and `context`. The `context` is a list of Type
	objects which represents the chain of nested objects that is being displayed.

	The `perform_get_lines_for_data` method returns a list of `DisassemblyTextLine` objects each one
	representing a single line of Linear View output. The `prefix` variable is a list of `InstructionTextToken`'s
	which have already been generated by other `DataRenderer`'s.

	After defining the `DataRenderer` subclass you must then register it with the core. This is done by calling
	either `register_type_specific` or `register_generic`. A "generic" type renderer is able to be overridden by
	a "type specific" renderer. For instance there is a generic struct render which renders any struct that hasn't
	been explicitly overridden by a "type specific" renderer.

	In the below example we create a data renderer that overrides the default display for `struct BAR`::

		class BarDataRenderer(DataRenderer):
			def __init__(self):
				DataRenderer.__init__(self)
			def perform_is_valid_for_data(self, ctxt, view, addr, type, context):
				return DataRenderer.is_type_of_struct_name(type, "BAR", context)
			def perform_get_lines_for_data(self, ctxt, view, addr, type, prefix, width, context):
				prefix.append(InstructionTextToken(InstructionTextTokenType.TextToken, "I'm in ur BAR"))
				return [DisassemblyTextLine(prefix, addr)]
			def __del__(self):
				pass

		BarDataRenderer().register_type_specific()

	Note that the formatting is sub-optimal to work around an issue with Sphinx and reStructured text
	)";
std::string test_54 = R"(
    ``class Database`` provides lower level access to raw snapshot data used to construct analysis data
    )";
std::string test_55 = R"(An enumeration.)";
std::string test_56 = R"(A warning class for deprecated methods

    This is a specialization of the built-in :class:`DeprecationWarning`,
    adding parameters that allow us to get information into the __str__
    that ends up being sent through the :mod:`warnings` system.
    The attributes aren't able to be retrieved after the warning gets
    raised and passed through the system as only the class--not the
    instance--and message are what gets preserved.

    :param function: The function being deprecated.
    :param deprecated_in: The version that ``function`` is deprecated in
    :param removed_in: The version or :class:`datetime.date` specifying
                       when ``function`` gets removed.
    :param details: Optional details about the deprecation. Most often
                    this will include directions on what to use instead
                    of the now deprecated code.
    )";
std::string test_57 = R"(
	``DirectoryNameField`` prompts the user to specify a directory name to open. Result is stored in self.result as
	a string.
	)";
std::string test_58 = R"(An enumeration.)";
std::string test_59 = R"(DisassemblyTextLine(tokens: List[ForwardRef('InstructionTextToken')], address: Optional[int] = None, il_instr: Union[ForwardRef('lowlevelil.LowLevelILInstruction'), ForwardRef('mediumlevelil.MediumLevelILInstruction'), ForwardRef('highlevelil.HighLevelILInstruction'), NoneType] = None, color: Union[ForwardRef('_highlight.HighlightColor'), binaryninja.enums.HighlightStandardColor, NoneType] = None))";
std::string test_60 = R"(DoublePrecision())";
std::string test_61 = R"(An enumeration.)";
std::string test_62 = R"(An enumeration.)";
std::string test_63 = R"(EntryRegisterValue(value: int = 0, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.EntryValue: 1>, confidence: int = 255, size: int = 0, reg: Optional[ForwardRef('binaryninja.architecture.RegisterName')] = None))";
std::string test_64 = R"(
    Generic enumeration.

    Derive from this class to define new enumerations.
    )";
std::string test_65 = R"(EnumerationMember(name: str, value: Optional[int] = None))";
std::string test_66 = R"(ExternalPointerRegisterValue(value: int, offset: int, type: binaryninja.enums.RegisterValueType = <RegisterValueType.ExternalPointerValue: 4>, confidence: int = 255, size: int = 0))";
std::string test_67 = R"(
	``class FileMetadata`` represents the file being analyzed by Binary Ninja. It is responsible for opening,
	closing, creating the database (.bndb) files, and is used to keep track of undoable actions.
	)";
std::string test_68 = R"(An enumeration.)";
std::string test_69 = R"(An enumeration.)";
std::string test_70 = R"(An enumeration.)";
std::string test_71 = R"(An enumeration.)";
std::string test_72 = R"(FloatingPoint())";
std::string test_73 = R"(
	``class FlowGraph`` implements a directed flow graph to be shown in the UI. This class allows plugins to
	create custom flow graphs and render them in the UI using the flow graph report API.

	An example of creating a flow graph and presenting it in the UI:

		>>> graph = FlowGraph()
		>>> node_a = FlowGraphNode(graph)
		>>> node_a.lines = ["Node A"]
		>>> node_b = FlowGraphNode(graph)
		>>> node_b.lines = ["Node B"]
		>>> node_c = FlowGraphNode(graph)
		>>> node_c.lines = ["Node C"]
		>>> graph.append(node_a)
		0
		>>> graph.append(node_b)
		1
		>>> graph.append(node_c)
		2
		>>> edge = EdgeStyle(EdgePenStyle.DashDotDotLine, 2, ThemeColor.AddressColor)
		>>> node_a.add_outgoing_edge(BranchType.UserDefinedBranch, node_b, edge)
		>>> node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_c)
		>>> show_graph_report("Custom Graph", graph)

	.. note:: In the current implementation, only graphs that have a single start node where all other nodes are 	reachable from outgoing edges can be rendered correctly. This describes the natural limitations of a control 	flow graph, which is what the rendering logic was designed for. Graphs that have nodes that are only reachable 	from incoming edges, or graphs that have disjoint subgraphs will not render correctly. This will be fixed 	in a future version.
	)";
std::string test_74 = R"(An enumeration.)";
std::string test_75 = R"(An enumeration.)";
std::string test_76 = R"(An enumeration.)";
std::string test_77 = R"(An enumeration.)";
std::string test_78 = R"(FunctionParameter(type: Union[ForwardRef('TypeBuilder'), ForwardRef('Type')], name: str = '', location: Optional[ForwardRef('variable.VariableNameAndType')] = None))";
std::string test_79 = R"(An enumeration.)";
std::string test_80 = R"(Abstract base class for generic types.

    A generic type is typically declared by inheriting from
    this class parameterized with one or more type variables.
    For example, a generic mapping type might be defined as::

      class Mapping(Generic[KT, VT]):
          def __getitem__(self, key: KT) -> VT:
              ...
          # Etc.

    This class can then be used as follows::

      def lookup_name(mapping: Mapping[KT, VT], key: KT, default: VT) -> VT:
          try:
              return mapping[key]
          except KeyError:
              return default
    )";
std::string test_81 = R"(GotoLabel(function: 'HighLevelILFunction', id: int))";
std::string test_82 = R"(HighLevelILAdc(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_83 = R"(HighLevelILAdd(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_84 = R"(HighLevelILAddOverflow(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_85 = R"(HighLevelILAddressOf(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_86 = R"(HighLevelILAnd(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_87 = R"(HighLevelILArrayIndex(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_88 = R"(HighLevelILArrayIndexSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_89 = R"(HighLevelILAsr(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_90 = R"(HighLevelILAssign(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_91 = R"(HighLevelILAssignMemSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_92 = R"(HighLevelILAssignUnpack(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_93 = R"(HighLevelILAssignUnpackMemSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_94 = R"(
	The ``HighLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	)";
std::string test_95 = R"(HighLevelILBinaryBase(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_96 = R"(HighLevelILBlock(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_97 = R"(HighLevelILBoolToInt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_98 = R"(HighLevelILBp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_99 = R"(HighLevelILBreak(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_100 = R"(HighLevelILCall(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_101 = R"(HighLevelILCallSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_102 = R"(HighLevelILCarryBase(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_103 = R"(HighLevelILCase(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_104 = R"(HighLevelILCeil(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_105 = R"(HighLevelILCmpE(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_106 = R"(HighLevelILCmpNe(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_107 = R"(HighLevelILCmpSge(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_108 = R"(HighLevelILCmpSgt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_109 = R"(HighLevelILCmpSle(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_110 = R"(HighLevelILCmpSlt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_111 = R"(HighLevelILCmpUge(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_112 = R"(HighLevelILCmpUgt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_113 = R"(HighLevelILCmpUle(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_114 = R"(HighLevelILCmpUlt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_115 = R"(HighLevelILComparisonBase(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_116 = R"(HighLevelILConst(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_117 = R"(HighLevelILConstData(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_118 = R"(HighLevelILConstPtr(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_119 = R"(HighLevelILContinue(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_120 = R"(HighLevelILDeref(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_121 = R"(HighLevelILDerefField(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_122 = R"(HighLevelILDerefFieldSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_123 = R"(HighLevelILDerefSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_124 = R"(HighLevelILDivs(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_125 = R"(HighLevelILDivsDp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_126 = R"(HighLevelILDivu(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_127 = R"(HighLevelILDivuDp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_128 = R"(HighLevelILDoWhile(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_129 = R"(HighLevelILDoWhileSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_130 = R"(
	``class HighLevelILExpr`` hold the index of IL Expressions.

	.. note:: Use ExpressionIndex instead
	)";
std::string test_131 = R"(HighLevelILExternPtr(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_132 = R"(HighLevelILFabs(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_133 = R"(HighLevelILFadd(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_134 = R"(HighLevelILFcmpE(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_135 = R"(HighLevelILFcmpGe(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_136 = R"(HighLevelILFcmpGt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_137 = R"(HighLevelILFcmpLe(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_138 = R"(HighLevelILFcmpLt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_139 = R"(HighLevelILFcmpNe(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_140 = R"(HighLevelILFcmpO(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_141 = R"(HighLevelILFcmpUo(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_142 = R"(HighLevelILFdiv(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_143 = R"(HighLevelILFloatConst(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_144 = R"(HighLevelILFloatConv(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_145 = R"(HighLevelILFloatToInt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_146 = R"(HighLevelILFloor(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_147 = R"(HighLevelILFmul(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_148 = R"(HighLevelILFneg(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_149 = R"(HighLevelILFor(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_150 = R"(HighLevelILForSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_151 = R"(HighLevelILFsqrt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_152 = R"(HighLevelILFsub(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_153 = R"(HighLevelILFtrunc(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_154 = R"(
	``class HighLevelILFunction`` contains the a HighLevelILInstruction object that makes up the abstract syntax tree of
	a function.
	)";
std::string test_155 = R"(HighLevelILGoto(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_156 = R"(HighLevelILIf(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_157 = R"(HighLevelILImport(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_158 = R"(
	``class HighLevelILInstruction`` High Level Intermediate Language Instructions form an abstract syntax tree of
	the code. Control flow structures are present as high level constructs in the HLIL tree.
	)";
std::string test_159 = R"(HighLevelILIntToFloat(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_160 = R"(HighLevelILIntrinsic(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_161 = R"(HighLevelILIntrinsicSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_162 = R"(HighLevelILJump(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_163 = R"(HighLevelILLabel(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_164 = R"(HighLevelILLowPart(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_165 = R"(HighLevelILLsl(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_166 = R"(HighLevelILLsr(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_167 = R"(HighLevelILMemPhi(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_168 = R"(HighLevelILMods(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_169 = R"(HighLevelILModsDp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_170 = R"(HighLevelILModu(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_171 = R"(HighLevelILModuDp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_172 = R"(HighLevelILMul(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_173 = R"(HighLevelILMulsDp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_174 = R"(HighLevelILMuluDp(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_175 = R"(HighLevelILNeg(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_176 = R"(HighLevelILNop(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_177 = R"(HighLevelILNoret(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_178 = R"(HighLevelILNot(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_179 = R"(An enumeration.)";
std::string test_180 = R"(HighLevelILOperationAndSize(operation: binaryninja.enums.HighLevelILOperation, size: int))";
std::string test_181 = R"(HighLevelILOr(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_182 = R"(HighLevelILRet(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_183 = R"(HighLevelILRlc(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_184 = R"(HighLevelILRol(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_185 = R"(HighLevelILRor(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_186 = R"(HighLevelILRoundToInt(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_187 = R"(HighLevelILRrc(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_188 = R"(HighLevelILSbb(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_189 = R"(HighLevelILSplit(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_190 = R"(HighLevelILStructField(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_191 = R"(HighLevelILSub(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_192 = R"(HighLevelILSwitch(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_193 = R"(HighLevelILSx(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_194 = R"(HighLevelILSyscall(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_195 = R"(HighLevelILSyscallSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_196 = R"(HighLevelILTailcall(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_197 = R"(HighLevelILTestBit(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_198 = R"(HighLevelILTrap(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_199 = R"(HighLevelILUnaryBase(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_200 = R"(HighLevelILUndef(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_201 = R"(HighLevelILUnimpl(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_202 = R"(HighLevelILUnimplMem(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_203 = R"(HighLevelILUnreachable(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_204 = R"(HighLevelILVar(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_205 = R"(HighLevelILVarDeclare(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_206 = R"(HighLevelILVarInit(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_207 = R"(HighLevelILVarInitSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_208 = R"(HighLevelILVarPhi(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_209 = R"(HighLevelILVarSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_210 = R"(HighLevelILWhile(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_211 = R"(HighLevelILWhileSsa(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_212 = R"(HighLevelILXor(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_213 = R"(HighLevelILZx(function: 'HighLevelILFunction', expr_index: binaryninja.highlevelil.ExpressionIndex, core_instr: binaryninja.highlevelil.CoreHighLevelILInstruction, as_ast: bool, instr_index: binaryninja.highlevelil.InstructionIndex))";
std::string test_214 = R"(HighlightColor(color=None, mix_color=None, mix=None, red=None, green=None, blue=None, alpha=255))";
std::string test_215 = R"(An enumeration.)";
std::string test_216 = R"(An enumeration.)";
std::string test_217 = R"(An enumeration.)";
std::string test_218 = R"(ILFlag(arch: 'architecture.Architecture', index: 'architecture.FlagIndex'))";
std::string test_219 = R"(An enumeration.)";
std::string test_220 = R"(ILIntrinsic(arch: 'architecture.Architecture', index: 'architecture.IntrinsicIndex'))";
std::string test_221 = R"(ILReferenceSource(func: Optional[ForwardRef('Function')], arch: Optional[ForwardRef('architecture.Architecture')], address: int, il_type: binaryninja.enums.FunctionGraphType, expr_id: int))";
std::string test_222 = R"(ILRegister(arch: 'architecture.Architecture', index: 'architecture.RegisterIndex'))";
std::string test_223 = R"(ILRegisterStack(arch: 'architecture.Architecture', index: 'architecture.RegisterStackIndex'))";
std::string test_224 = R"(ILSemanticFlagClass(arch: 'architecture.Architecture', index: 'architecture.SemanticClassIndex'))";
std::string test_225 = R"(ILSemanticFlagGroup(arch: 'architecture.Architecture', index: 'architecture.SemanticGroupIndex'))";
std::string test_226 = R"(An enumeration.)";
std::string test_227 = R"(ImportedAddressRegisterValue(value: int, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.ImportedAddressValue: 7>, confidence: int = 255, size: int = 0))";
std::string test_228 = R"(IndirectBranchInfo(source_arch: 'binaryninja.architecture.Architecture', source_addr: int, dest_arch: 'binaryninja.architecture.Architecture', dest_addr: int, auto_defined: bool))";
std::string test_229 = R"(InheritedStructureMember(base: 'NamedTypeReferenceType', base_offset: int, member: binaryninja.types.StructureMember, member_index: int))";
std::string test_230 = R"(InstructionBranch(type: binaryninja.enums.BranchType, target: int, arch: Optional[ForwardRef('Architecture')]))";
std::string test_231 = R"(InstructionInfo(length: int = 0, arch_transition_by_target_addr: bool = False, branch_delay: bool = False, branches: List[binaryninja.architecture.InstructionBranch] = <factory>))";
std::string test_232 = R"(
	``class InstructionTextToken`` is used to tell the core about the various components in the disassembly views.

	The below table is provided for documentation purposes but the complete list of TokenTypes is available at: :class:`!enums.InstructionTextTokenType`. Note that types marked as `Not emitted by architectures` are not intended to be used by Architectures during lifting. Rather, they are added by the core during analysis or display. UI plugins, however, may make use of them as appropriate.

	Uses of tokens include plugins that parse the output of an architecture (though parsing IL is recommended), or additionally, applying color schemes appropriately.

		========================== ============================================
		InstructionTextTokenType   Description
		========================== ============================================
		AddressDisplayToken        **Not emitted by architectures**
		AnnotationToken            **Not emitted by architectures**
		ArgumentNameToken          **Not emitted by architectures**
		BeginMemoryOperandToken    The start of memory operand
		CharacterConstantToken     A printable character
		CodeRelativeAddressToken   **Not emitted by architectures**
		CodeSymbolToken            **Not emitted by architectures**
		DataSymbolToken            **Not emitted by architectures**
		EndMemoryOperandToken      The end of a memory operand
		ExternalSymbolToken        **Not emitted by architectures**
		FieldNameToken             **Not emitted by architectures**
		FloatingPointToken         Floating point number
		HexDumpByteValueToken      **Not emitted by architectures**
		HexDumpInvalidByteToken    **Not emitted by architectures**
		HexDumpSkippedByteToken    **Not emitted by architectures**
		HexDumpTextToken           **Not emitted by architectures**
		ImportToken                **Not emitted by architectures**
		IndirectImportToken        **Not emitted by architectures**
		InstructionToken           The instruction mnemonic
		IntegerToken               Integers
		KeywordToken               **Not emitted by architectures**
		LocalVariableToken         **Not emitted by architectures**
		NameSpaceSeparatorToken    **Not emitted by architectures**
		NameSpaceToken             **Not emitted by architectures**
		OpcodeToken                **Not emitted by architectures**
		OperandSeparatorToken      The comma or delimiter that separates tokens
		PossibleAddressToken       Integers that are likely addresses
		RegisterToken              Registers
		StringToken                **Not emitted by architectures**
		StructOffsetToken          **Not emitted by architectures**
		TagToken                   **Not emitted by architectures**
		TextToken                  Used for anything not of another type.
		CommentToken               Comments
		TypeNameToken              **Not emitted by architectures**
		========================== ============================================

	)";
std::string test_233 = R"(An enumeration.)";
std::string test_234 = R"(An enumeration.)";
std::string test_235 = R"(
    Support for integer-based Flags
    )";
std::string test_236 = R"(An enumeration.)";
std::string test_237 = R"(
	``IntegerField`` add prompt for integer. Result is stored in self.result as an int.
	)";
std::string test_238 = R"(Intrinsic())";
std::string test_239 = R"(IntrinsicInfo(inputs: List[binaryninja.architecture.IntrinsicInput], outputs: List[ForwardRef('types.Type')], index: Optional[int] = None))";
std::string test_240 = R"(IntrinsicInput(type: 'types.Type', name: str = ''))";
std::string test_241 = R"(
    ``class KeyValueStore`` maintains access to the raw data stored in Snapshots and various
    other Database-related structures.
    )";
std::string test_242 = R"(
	``LabelField`` adds a text label to the display.
	)";
std::string test_243 = R"(
	.. note: This object is only available in the Enterprise edition of Binary Ninja.

	Helper class for scripts to make use of a license checkout in a scope.

	:Example:
		>>> enterprise.connect()
		>>> enterprise.authenticate_with_credentials("username", "password")
		>>> with enterprise.LicenseCheckout():
		... 	# Do some operation
		... 	with load("/bin/ls") as bv: # e.g.
		... 		print(hex(bv.start))
		# License is released at end of scope
	)";
std::string test_244 = R"(An enumeration.)";
std::string test_245 = R"(An enumeration.)";
std::string test_246 = R"(Load())";
std::string test_247 = R"(Localcall())";
std::string test_248 = R"(An enumeration.)";
std::string test_249 = R"(LookupTableEntry(from_values: List[int], to_value: int, type: binaryninja.enums.RegisterValueType = <RegisterValueType.LookupTableValue: 10>))";
std::string test_250 = R"(Loop())";
std::string test_251 = R"(LowLevelILAdc(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_252 = R"(LowLevelILAdd(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_253 = R"(LowLevelILAddOverflow(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_254 = R"(LowLevelILAnd(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_255 = R"(LowLevelILAsr(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_256 = R"(
	The ``LogLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	)";
std::string test_257 = R"(LowLevelILBinaryBase(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_258 = R"(LowLevelILBoolToInt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_259 = R"(LowLevelILBp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_260 = R"(LowLevelILCall(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_261 = R"(LowLevelILCallOutputSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_262 = R"(LowLevelILCallParam(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_263 = R"(LowLevelILCallSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_264 = R"(LowLevelILCallStackAdjust(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_265 = R"(LowLevelILCallStackSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_266 = R"(LowLevelILCarryBase(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_267 = R"(LowLevelILCeil(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_268 = R"(LowLevelILCmpE(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_269 = R"(LowLevelILCmpNe(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_270 = R"(LowLevelILCmpSge(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_271 = R"(LowLevelILCmpSgt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_272 = R"(LowLevelILCmpSle(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_273 = R"(LowLevelILCmpSlt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_274 = R"(LowLevelILCmpUge(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_275 = R"(LowLevelILCmpUgt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_276 = R"(LowLevelILCmpUle(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_277 = R"(LowLevelILCmpUlt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_278 = R"(LowLevelILComparisonBase(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_279 = R"(LowLevelILConst(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_280 = R"(LowLevelILConstPtr(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_281 = R"(LowLevelILConstantBase(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_282 = R"(LowLevelILDivs(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_283 = R"(LowLevelILDivsDp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_284 = R"(LowLevelILDivu(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_285 = R"(LowLevelILDivuDp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_286 = R"(
	``class LowLevelILExpr`` hold the index of IL Expressions.

	.. note:: Deprecated. Use ExpressionIndex instead
	)";
std::string test_287 = R"(LowLevelILExternPtr(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_288 = R"(LowLevelILFabs(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_289 = R"(LowLevelILFadd(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_290 = R"(LowLevelILFcmpE(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_291 = R"(LowLevelILFcmpGe(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_292 = R"(LowLevelILFcmpGt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_293 = R"(LowLevelILFcmpLe(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_294 = R"(LowLevelILFcmpLt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_295 = R"(LowLevelILFcmpNe(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_296 = R"(LowLevelILFcmpO(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_297 = R"(LowLevelILFcmpUo(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_298 = R"(LowLevelILFdiv(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_299 = R"(LowLevelILFlag(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_300 = R"(LowLevelILFlagBit(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_301 = R"(LowLevelILFlagBitSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_302 = R"(LowLevelILFlagCond(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_303 = R"(An enumeration.)";
std::string test_304 = R"(LowLevelILFlagGroup(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_305 = R"(LowLevelILFlagPhi(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_306 = R"(LowLevelILFlagSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_307 = R"(LowLevelILFloatConst(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_308 = R"(LowLevelILFloatConv(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_309 = R"(LowLevelILFloatToInt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_310 = R"(LowLevelILFloor(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_311 = R"(LowLevelILFmul(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_312 = R"(LowLevelILFneg(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_313 = R"(LowLevelILFsqrt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_314 = R"(LowLevelILFsub(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_315 = R"(LowLevelILFtrunc(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_316 = R"(
	``class LowLevelILFunction`` contains the list of ExpressionIndex objects that make up a function. ExpressionIndex
	objects can be added to the LowLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return ExpressionIndex objects.


	LowLevelILFlagCondition values used as parameters in the :func:`flag_condition` method.

		======================= ========== ===============================
		LowLevelILFlagCondition Operator   Description
		======================= ========== ===============================
		LLFC_E                  ==         Equal
		LLFC_NE                 !=         Not equal
		LLFC_SLT                s<         Signed less than
		LLFC_ULT                u<         Unsigned less than
		LLFC_SLE                s<=        Signed less than or equal
		LLFC_ULE                u<=        Unsigned less than or equal
		LLFC_SGE                s>=        Signed greater than or equal
		LLFC_UGE                u>=        Unsigned greater than or equal
		LLFC_SGT                s>         Signed greater than
		LLFC_UGT                u>         Unsigned greater than
		LLFC_NEG                -          Negative
		LLFC_POS                +          Positive
		LLFC_O                  overflow   Overflow
		LLFC_NO                 !overflow  No overflow
		======================= ========== ===============================
	)";
std::string test_317 = R"(LowLevelILGoto(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_318 = R"(LowLevelILIf(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_319 = R"(
	``class LowLevelILInstruction`` Low Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. LLIL ``eax = 0``).
	)";
std::string test_320 = R"(LowLevelILIntToFloat(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_321 = R"(LowLevelILIntrinsic(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_322 = R"(LowLevelILIntrinsicSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_323 = R"(LowLevelILJump(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_324 = R"(LowLevelILJumpTo(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_325 = R"(LowLevelILLoad(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_326 = R"(LowLevelILLoadSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_327 = R"(LowLevelILLowPart(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_328 = R"(LowLevelILLsl(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_329 = R"(LowLevelILLsr(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_330 = R"(LowLevelILMemPhi(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_331 = R"(LowLevelILMods(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_332 = R"(LowLevelILModsDp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_333 = R"(LowLevelILModu(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_334 = R"(LowLevelILModuDp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_335 = R"(LowLevelILMul(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_336 = R"(LowLevelILMulsDp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_337 = R"(LowLevelILMuluDp(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_338 = R"(LowLevelILNeg(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_339 = R"(LowLevelILNop(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_340 = R"(LowLevelILNoret(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_341 = R"(LowLevelILNot(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_342 = R"(An enumeration.)";
std::string test_343 = R"(LowLevelILOperationAndSize(operation: 'LowLevelILOperation', size: int))";
std::string test_344 = R"(LowLevelILOr(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_345 = R"(LowLevelILPop(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_346 = R"(LowLevelILPush(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_347 = R"(LowLevelILReg(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_348 = R"(LowLevelILRegPhi(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_349 = R"(LowLevelILRegSplit(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_350 = R"(LowLevelILRegSplitDestSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_351 = R"(LowLevelILRegSplitSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_352 = R"(LowLevelILRegSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_353 = R"(LowLevelILRegSsaPartial(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_354 = R"(LowLevelILRegStackAbsSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_355 = R"(LowLevelILRegStackDestSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_356 = R"(LowLevelILRegStackFreeAbsSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_357 = R"(LowLevelILRegStackFreeReg(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_358 = R"(LowLevelILRegStackFreeRel(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_359 = R"(LowLevelILRegStackFreeRelSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_360 = R"(LowLevelILRegStackPhi(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_361 = R"(LowLevelILRegStackPop(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_362 = R"(LowLevelILRegStackPush(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_363 = R"(LowLevelILRegStackRel(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_364 = R"(LowLevelILRegStackRelSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_365 = R"(LowLevelILRet(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_366 = R"(LowLevelILRlc(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_367 = R"(LowLevelILRol(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_368 = R"(LowLevelILRor(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_369 = R"(LowLevelILRoundToInt(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_370 = R"(LowLevelILRrc(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_371 = R"(LowLevelILSbb(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_372 = R"(LowLevelILSetFlag(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_373 = R"(LowLevelILSetFlagSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_374 = R"(LowLevelILSetReg(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_375 = R"(LowLevelILSetRegSplit(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_376 = R"(LowLevelILSetRegSplitSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_377 = R"(LowLevelILSetRegSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_378 = R"(LowLevelILSetRegSsaPartial(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_379 = R"(LowLevelILSetRegStackAbsSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_380 = R"(LowLevelILSetRegStackRel(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_381 = R"(LowLevelILSetRegStackRelSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_382 = R"(LowLevelILStore(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_383 = R"(LowLevelILStoreSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_384 = R"(LowLevelILSub(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_385 = R"(LowLevelILSx(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_386 = R"(LowLevelILSyscall(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_387 = R"(LowLevelILSyscallSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_388 = R"(LowLevelILTailcall(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_389 = R"(LowLevelILTailcallSsa(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_390 = R"(LowLevelILTestBit(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_391 = R"(LowLevelILTrap(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_392 = R"(LowLevelILUnaryBase(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_393 = R"(LowLevelILUndef(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_394 = R"(LowLevelILUnimpl(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_395 = R"(LowLevelILUnimplMem(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_396 = R"(LowLevelILXor(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_397 = R"(LowLevelILZx(function: 'LowLevelILFunction', expr_index: binaryninja.lowlevelil.ExpressionIndex, instr: binaryninja.lowlevelil.CoreLowLevelILInstruction, instr_index: Optional[binaryninja.lowlevelil.InstructionIndex]))";
std::string test_398 = R"(MediumLevelILAdc(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_399 = R"(MediumLevelILAdd(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_400 = R"(MediumLevelILAddOverflow(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_401 = R"(MediumLevelILAddressOf(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_402 = R"(MediumLevelILAddressOfField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_403 = R"(MediumLevelILAnd(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_404 = R"(MediumLevelILAsr(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_405 = R"(
	The ``MediumLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	)";
std::string test_406 = R"(MediumLevelILBinaryBase(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_407 = R"(MediumLevelILBoolToInt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_408 = R"(MediumLevelILBp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_409 = R"(MediumLevelILCall(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_410 = R"(MediumLevelILCallBase(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_411 = R"(MediumLevelILCallOutput(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_412 = R"(MediumLevelILCallOutputSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_413 = R"(MediumLevelILCallParam(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_414 = R"(MediumLevelILCallParamSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_415 = R"(MediumLevelILCallSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_416 = R"(MediumLevelILCallUntyped(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_417 = R"(MediumLevelILCallUntypedSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_418 = R"(MediumLevelILCarryBase(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_419 = R"(MediumLevelILCeil(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_420 = R"(MediumLevelILCmpE(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_421 = R"(MediumLevelILCmpNe(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_422 = R"(MediumLevelILCmpSge(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_423 = R"(MediumLevelILCmpSgt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_424 = R"(MediumLevelILCmpSle(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_425 = R"(MediumLevelILCmpSlt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_426 = R"(MediumLevelILCmpUge(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_427 = R"(MediumLevelILCmpUgt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_428 = R"(MediumLevelILCmpUle(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_429 = R"(MediumLevelILCmpUlt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_430 = R"(MediumLevelILComparisonBase(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_431 = R"(MediumLevelILConst(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_432 = R"(MediumLevelILConstBase(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_433 = R"(MediumLevelILConstData(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_434 = R"(MediumLevelILConstPtr(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_435 = R"(MediumLevelILDivs(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_436 = R"(MediumLevelILDivsDp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_437 = R"(MediumLevelILDivu(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_438 = R"(MediumLevelILDivuDp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_439 = R"(
	``class MediumLevelILExpr`` hold the index of IL Expressions.

	.. note:: Deprecated. Use ExpressionIndex instead
	)";
std::string test_440 = R"(MediumLevelILExternPtr(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_441 = R"(MediumLevelILFabs(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_442 = R"(MediumLevelILFadd(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_443 = R"(MediumLevelILFcmpE(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_444 = R"(MediumLevelILFcmpGe(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_445 = R"(MediumLevelILFcmpGt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_446 = R"(MediumLevelILFcmpLe(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_447 = R"(MediumLevelILFcmpLt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_448 = R"(MediumLevelILFcmpNe(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_449 = R"(MediumLevelILFcmpO(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_450 = R"(MediumLevelILFcmpUo(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_451 = R"(MediumLevelILFdiv(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_452 = R"(MediumLevelILFloatConst(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_453 = R"(MediumLevelILFloatConv(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_454 = R"(MediumLevelILFloatToInt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_455 = R"(MediumLevelILFloor(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_456 = R"(MediumLevelILFmul(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_457 = R"(MediumLevelILFneg(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_458 = R"(MediumLevelILFreeVarSlot(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_459 = R"(MediumLevelILFreeVarSlotSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_460 = R"(MediumLevelILFsqrt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_461 = R"(MediumLevelILFsub(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_462 = R"(MediumLevelILFtrunc(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_463 = R"(
	``class MediumLevelILFunction`` contains the list of ExpressionIndex objects that make up a function. ExpressionIndex
	objects can be added to the MediumLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return ExpressionIndex objects.
	)";
std::string test_464 = R"(MediumLevelILGoto(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_465 = R"(MediumLevelILIf(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_466 = R"(MediumLevelILImport(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_467 = R"(
	``class MediumLevelILInstruction`` Medium Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. MLIL ``eax = 0``).
	)";
std::string test_468 = R"(MediumLevelILIntToFloat(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_469 = R"(MediumLevelILIntrinsic(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_470 = R"(MediumLevelILIntrinsicSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_471 = R"(MediumLevelILJump(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_472 = R"(MediumLevelILJumpTo(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_473 = R"(MediumLevelILLoad(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_474 = R"(MediumLevelILLoadSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_475 = R"(MediumLevelILLoadStruct(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_476 = R"(MediumLevelILLoadStructSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_477 = R"(MediumLevelILLowPart(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_478 = R"(MediumLevelILLsl(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_479 = R"(MediumLevelILLsr(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_480 = R"(MediumLevelILMemPhi(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_481 = R"(MediumLevelILMods(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_482 = R"(MediumLevelILModsDp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_483 = R"(MediumLevelILModu(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_484 = R"(MediumLevelILModuDp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_485 = R"(MediumLevelILMul(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_486 = R"(MediumLevelILMulsDp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_487 = R"(MediumLevelILMuluDp(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_488 = R"(MediumLevelILNeg(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_489 = R"(MediumLevelILNop(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_490 = R"(MediumLevelILNoret(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_491 = R"(MediumLevelILNot(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_492 = R"(An enumeration.)";
std::string test_493 = R"(MediumLevelILOperationAndSize(operation: binaryninja.enums.MediumLevelILOperation, size: int))";
std::string test_494 = R"(MediumLevelILOr(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_495 = R"(MediumLevelILRet(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_496 = R"(MediumLevelILRetHint(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_497 = R"(MediumLevelILRlc(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_498 = R"(MediumLevelILRol(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_499 = R"(MediumLevelILRor(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_500 = R"(MediumLevelILRoundToInt(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_501 = R"(MediumLevelILRrc(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_502 = R"(MediumLevelILSbb(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_503 = R"(MediumLevelILSetVar(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_504 = R"(MediumLevelILSetVarAliased(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_505 = R"(MediumLevelILSetVarAliasedField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_506 = R"(MediumLevelILSetVarField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_507 = R"(MediumLevelILSetVarSplit(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_508 = R"(MediumLevelILSetVarSplitSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_509 = R"(MediumLevelILSetVarSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_510 = R"(MediumLevelILSetVarSsaField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_511 = R"(MediumLevelILStore(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_512 = R"(MediumLevelILStoreSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_513 = R"(MediumLevelILStoreStruct(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_514 = R"(MediumLevelILStoreStructSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_515 = R"(MediumLevelILSub(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_516 = R"(MediumLevelILSx(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_517 = R"(MediumLevelILSyscall(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_518 = R"(MediumLevelILSyscallSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_519 = R"(MediumLevelILSyscallUntyped(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_520 = R"(MediumLevelILSyscallUntypedSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_521 = R"(MediumLevelILTailcall(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_522 = R"(MediumLevelILTailcallSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_523 = R"(MediumLevelILTailcallUntyped(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_524 = R"(MediumLevelILTailcallUntypedSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_525 = R"(MediumLevelILTestBit(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_526 = R"(MediumLevelILTrap(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_527 = R"(MediumLevelILUnaryBase(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_528 = R"(MediumLevelILUndef(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_529 = R"(MediumLevelILUnimpl(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_530 = R"(MediumLevelILUnimplMem(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_531 = R"(MediumLevelILVar(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_532 = R"(MediumLevelILVarAliased(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_533 = R"(MediumLevelILVarAliasedField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_534 = R"(MediumLevelILVarField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_535 = R"(MediumLevelILVarPhi(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_536 = R"(MediumLevelILVarSplit(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_537 = R"(MediumLevelILVarSplitSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_538 = R"(MediumLevelILVarSsa(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_539 = R"(MediumLevelILVarSsaField(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_540 = R"(MediumLevelILXor(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_541 = R"(MediumLevelILZx(function: 'MediumLevelILFunction', expr_index: binaryninja.mediumlevelil.ExpressionIndex, instr: binaryninja.mediumlevelil.CoreMediumLevelILInstruction, instr_index: binaryninja.mediumlevelil.InstructionIndex))";
std::string test_542 = R"(An enumeration.)";
std::string test_543 = R"(int([x]) -> integer
int(x, base=10) -> integer

Convert a number or string to an integer, or return 0 if no arguments
are given.  If x is a number, return x.__int__().  For floating point
numbers, this truncates towards zero.

If x is not a number or if base is given, then x must be a string,
bytes, or bytearray instance representing an integer literal in the
given base.  The literal can be preceded by '+' or '-' and be surrounded
by whitespace.  The base defaults to 10.  Valid bases are 0 and 2-36.
Base 0 means to interpret the base from the string as an integer literal.
>>> int('0b100', base=0)
4)";
std::string test_544 = R"(str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to sys.getdefaultencoding().
errors defaults to 'strict'.)";
std::string test_545 = R"(int([x]) -> integer
int(x, base=10) -> integer

Convert a number or string to an integer, or return 0 if no arguments
are given.  If x is a number, return x.__int__().  For floating point
numbers, this truncates towards zero.

If x is not a number or if base is given, then x must be a string,
bytes, or bytearray instance representing an integer literal in the
given base.  The literal can be preceded by '+' or '-' and be surrounded
by whitespace.  The base defaults to 10.  Valid bases are 0 and 2-36.
Base 0 means to interpret the base from the string as an integer literal.
>>> int('0b100', base=0)
4)";
std::string test_546 = R"(An enumeration.)";
std::string test_547 = R"(Memory())";
std::string test_548 = R"(An enumeration.)";
std::string test_549 = R"(An enumeration.)";
std::string test_550 = R"(An enumeration.)";
std::string test_551 = R"(An enumeration.)";
std::string test_552 = R"(An enumeration.)";
std::string test_553 = R"(
	``MultilineTextField`` add multi-line text string input field. Result is stored in self.result
	as a string. This option is not supported on the command-line.
	)";
std::string test_554 = R"(MutableTypeBuilder(type: ~TB, container: Union[ForwardRef('binaryview.BinaryView'), ForwardRef('typelibrary.TypeLibrary')], name: binaryninja.types.QualifiedName, platform: Optional[ForwardRef('_platform.Platform')], confidence: int, user: bool = True))";
std::string test_555 = R"(An enumeration.)";
std::string test_556 = R"(An enumeration.)";
std::string test_557 = R"(NewType creates simple unique types with almost zero
    runtime overhead. NewType(name, tp) is considered a subtype of tp
    by static type checkers. At runtime, NewType(name, tp) returns
    a dummy callable that simply returns its argument. Usage::

        UserId = NewType('UserId', int)

        def name_by_id(user_id: UserId) -> str:
            ...

        UserId('user')          # Fails type check

        name_by_id(42)          # Fails type check
        name_by_id(UserId(42))  # OK

        num = UserId(5) + 1     # type: int
    )";
std::string test_558 = R"(An enumeration.)";
std::string test_559 = R"(OffsetWithConfidence(value: int, confidence: int = 255))";
std::string test_560 = R"(
	``OpenFileNameField`` prompts the user to specify a file name to open. Result is stored in self.result as a string.
	)";
std::string test_561 = R"(Dictionary that remembers insertion order)";
std::string test_562 = R"(

	.. note:: This object is a "passive" object. Any changes you make to it will not be reflected in the core and vice-versa. If you wish to update a core version of this object you should use the appropriate API.
)";
std::string test_563 = R"(ParsedType(name: 'types.QualifiedNameType', type: 'types.Type', is_user: bool))";
std::string test_564 = R"(PurePath subclass that can make system calls.

    Path represents a filesystem path but unlike PurePath, also offers
    methods to do system calls on path objects. Depending on your system,
    instantiating a Path will return either a PosixPath or a WindowsPath
    object. You can also instantiate a PosixPath or WindowsPath directly,
    but cannot instantiate a WindowsPath on a POSIX system or vice versa.
    )";
std::string test_565 = R"(Phi())";
std::string test_566 = R"(
	``class Platform`` contains all information related to the execution environment of the binary, mainly the
	calling conventions used.
	)";
std::string test_567 = R"(An enumeration.)";
std::string test_568 = R"(An enumeration.)";
std::string test_569 = R"(An enumeration.)";
std::string test_570 = R"(An enumeration.)";
std::string test_571 = R"(An enumeration.)";
std::string test_572 = R"(An enumeration.)";
std::string test_573 = R"(An enumeration.)";
std::string test_574 = R"(
	`class PossibleValueSet` PossibleValueSet is used to define possible values
	that a variable can take. It contains methods to instantiate different
	value sets such as Constant, Signed/Unsigned Ranges, etc.
	

	.. note:: This object is a "passive" object. Any changes you make to it will not be reflected in the core and vice-versa. If you wish to update a core version of this object you should use the appropriate API.
)";
std::string test_575 = R"(QualifiedNameTypeAndId(name: 'types.QualifiedNameType', id: str, type: 'types.Type'))";
std::string test_576 = R"(ReferenceSource(function: Optional[ForwardRef('_function.Function')], arch: Optional[ForwardRef('architecture.Architecture')], address: int))";
std::string test_577 = R"(An enumeration.)";
std::string test_578 = R"(RegisterInfo(full_width_reg: binaryninja.architecture.RegisterName, size: int, offset: int = 0, extend: binaryninja.enums.ImplicitRegisterExtend = <ImplicitRegisterExtend.NoExtend: 0>, index: Optional[binaryninja.architecture.RegisterIndex] = None))";
std::string test_579 = R"(RegisterSet(regs: List[ForwardRef('architecture.RegisterName')], confidence: int = 255))";
std::string test_580 = R"(RegisterStack())";
std::string test_581 = R"(RegisterStackAdjustmentWithConfidence(value: int, confidence: int = 255))";
std::string test_582 = R"(RegisterStackInfo(storage_regs: List[binaryninja.architecture.RegisterName], top_relative_regs: List[binaryninja.architecture.RegisterName], stack_top_reg: binaryninja.architecture.RegisterName, index: Optional[binaryninja.architecture.RegisterStackIndex] = None))";
std::string test_583 = R"(RegisterValue(value: int, offset: int, type: binaryninja.enums.RegisterValueType = <RegisterValueType.UndeterminedValue: 0>, confidence: int = 255, size: int = 0))";
std::string test_584 = R"(An enumeration.)";
std::string test_585 = R"(An enumeration.)";
std::string test_586 = R"( Exception raised when a relocation fails to apply )";
std::string test_587 = R"(
	``RepoPlugin`` is mostly read-only, however you can install/uninstall enable/disable plugins. RepoPlugins are
	created by parsing the plugins.json in a plugin repository.
	)";
std::string test_588 = R"(An enumeration.)";
std::string test_589 = R"(
	``Repository`` is a read-only class. Use RepositoryManager to Enable/Disable/Install/Uninstall plugins.
	)";
std::string test_590 = R"(
	``RepositoryManager`` Keeps track of all the repositories and keeps the enabled_plugins.json file coherent with
	the plugins that are installed/uninstalled enabled/disabled
	)";
std::string test_591 = R"(Return())";
std::string test_592 = R"(ReturnAddressRegisterValue(value: int, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.ReturnAddressValue: 6>, confidence: int = 255, size: int = 0))";
std::string test_593 = R"(SSA())";
std::string test_594 = R"(SSAFlag(flag: binaryninja.lowlevelil.ILFlag, version: int))";
std::string test_595 = R"(SSARegister(reg: binaryninja.lowlevelil.ILRegister, version: int))";
std::string test_596 = R"(SSARegisterOrFlag(reg_or_flag: Union[binaryninja.lowlevelil.ILRegister, binaryninja.lowlevelil.ILFlag], version: int))";
std::string test_597 = R"(SSARegisterStack(reg_stack: binaryninja.lowlevelil.ILRegisterStack, version: int))";
std::string test_598 = R"(SSAVariable(var: 'variable.Variable', version: int))";
std::string test_599 = R"(SSAVariableInstruction())";
std::string test_600 = R"(
	``SaveFileNameField`` prompts the user to specify a file name to save. Result is stored in self.result as a string.
	)";
std::string test_601 = R"(An enumeration.)";
std::string test_602 = R"(
	``class SaveSettings`` is used to specify actions and options that apply to saving a database (.bndb).
	)";
std::string test_603 = R"(An enumeration.)";
std::string test_604 = R"(An enumeration.)";
std::string test_605 = R"(
	The ``Section`` object is returned during BinaryView creation and should not be directly instantiated.
	)";
std::string test_606 = R"(An enumeration.)";
std::string test_607 = R"(
	The ``Segment`` object is returned during BinaryView creation and should not be directly instantiated.
	)";
std::string test_608 = R"(An enumeration.)";
std::string test_609 = R"(
	``SeparatorField`` adds vertical separation to the display.
	)";
std::string test_610 = R"(SetReg())";
std::string test_611 = R"(SetVar())";
std::string test_612 = R"(
	:class:`Settings` provides a way to define and access settings in a hierarchical fashion. The value of a setting can 	be defined for each hierarchical level, where each level overrides the preceding level. The backing-store for setting 	values at each level is also configurable. This allows for ephemeral or platform-independent persistent settings storage 	for components within Binary Ninja or consumers of the Binary Ninja API.

	Each :class:`Settings` instance has an ``instance_id`` which identifies a schema. The schema defines the settings contents  	and the way in which settings are retrieved and manipulated. A new :class:`Settings` instance defaults to using a value of *'default'* 	for the ``instance_id``. The *'default'* settings schema defines all of the settings available for the active Binary Ninja components 	which include at a minimum, the settings defined by the Binary Ninja core. The *'default'* schema may additionally define settings 	for the UI and/or installed plugins. Extending existing schemas, or defining new ones is accomplished by calling :func:`register_group` 	and :func:`register_setting` methods, or by deserializing an existing schema with :func:`deserialize_schema`.

	.. note:: All settings in the *'default'* settings schema are rendered with UI elements in the Settings View of Binary Ninja UI.

	Allowing setting overrides is an important feature and Binary Ninja accomplishes this by allowing one to override a setting at various 	levels. The levels and their associated storage are shown in the following table. Default setting values are optional, and if specified, 	saved in the schema itself.

		================= ========================== ============== ==============================================
		Setting Level     Settings Scope             Preference     Storage
		================= ========================== ============== ==============================================
		Default           SettingsDefaultScope       Lowest         Settings Schema
		User              SettingsUserScope          -              <User Directory>/settings.json
		Project           SettingsProjectScope       -              <Project Directory>/.binaryninja/settings.json
		Resource          SettingsResourceScope      Highest        Raw BinaryView (Storage in BNDB)
		================= ========================== ============== ==============================================

	Settings are identified by a key, which is a string in the form of **'<group>.<name>'** or **'<group>.<subGroup>.<name>'**. Groups provide 	a simple way to categorize settings. Sub-groups are optional and multiple sub-groups are allowed. When defining a settings group, the 	:func:`register_group` method allows for specifying a UI friendly title for use in the Binary Ninja UI. Defining a new setting requires a 	unique setting key and a JSON string of property, value pairs. The following table describes the available properties and values.

		==================   ======================================   ==================   ========   =======================================================================
		Property             JSON Data Type                           Prerequisite         Optional   {Allowed Values} and Notes
		==================   ======================================   ==================   ========   =======================================================================
		"title"              string                                   None                 No         Concise Setting Title
		"type"               string                                   None                 No         {"array", "boolean", "number", "string"}
		"elementType"        string                                   "type" is "array"    No         {"string"}
		"enum"               array : {string}                         "type" is "string"   Yes        Enumeration definitions
		"enumDescriptions"   array : {string}                         "type" is "string"   Yes        Enumeration descriptions that match "enum" array
		"minValue"           number                                   "type" is "number"   Yes        Specify 0 to infer unsigned (default is signed)
		"maxValue"           number                                   "type" is "number"   Yes        Values less than or equal to INT_MAX result in a QSpinBox UI element
		"precision"          number                                   "type" is "number"   Yes        Specify precision for a QDoubleSpinBox
		"default"            {array, boolean, number, string, null}   None                 Yes        Specify optimal default value
		"aliases"            array : {string}                         None                 Yes        Array of deprecated setting key(s)
		"description"        string                                   None                 No         Detailed setting description
		"ignore"             array : {string}                         None                 Yes        {"SettingsUserScope", "SettingsProjectScope", "SettingsResourceScope"}
		"message"            string                                   None                 Yes        An optional message with additional emphasis
		"readOnly"           boolean                                  None                 Yes        Only enforced by UI elements
		"optional"           boolean                                  None                 Yes        Indicates setting can be null
		"requiresRestart     boolean                                  None                 Yes        Enable restart notification in the UI upon change
		==================   ======================================   ==================   ========   =======================================================================

	.. note:: In order to facilitate deterministic analysis results, settings from the *'default'* schema that impact analysis are serialized 	from Default, User, and Project scope into Resource scope during initial BinaryView analysis. This allows an analysis database to be opened 	at a later time with the same settings, regardless if Default, User, or Project settings have been modified.

	.. note:: Settings that do not impact analysis (e.g. many UI settings) should use the *"ignore"* property to exclude 		*"SettingsProjectScope"* and *"SettingsResourceScope"* from the applicable scopes for the setting.

	Example analysis plugin setting:

		>>> my_settings = Settings()
		>>> title = "My Pre-Analysis Plugin"
		>>> description = "Enable extra analysis before core analysis."
		>>> properties = f'{{"title" : "{title}", "description" : "{description}", "type" : "boolean", "default" : false}}'
		>>> my_settings.register_group("myPlugin", "My Plugin")
		True
		>>> my_settings.register_setting("myPlugin.enablePreAnalysis", properties)
		True
		>>> my_bv = load("/bin/ls", options={'myPlugin.enablePreAnalysis' : True})
		>>> Settings().get_bool("myPlugin.enablePreAnalysis")
		False
		>>> Settings().get_bool("myPlugin.enablePreAnalysis", my_bv)
		True

	Example UI plugin setting:

		>>> my_settings = Settings()
		>>> title = "My UI Plugin"
		>>> description = "Enable My UI Plugin table display."
		>>> properties = f'{{"title" : "{title}", "description" : "{description}", "type" : "boolean", "default" : true, "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}}'
		>>> my_settings.register_group("myPlugin", "My Plugin")
		True
		>>> my_settings.register_setting("myPlugin.enableTableView", properties)
		True
		>>> my_bv = load("/bin/ls", options={'myPlugin.enableTableView' : True})
		>>> Settings().get_bool("myPlugin.enableTableView")
		True

	)";
std::string test_613 = R"(An enumeration.)";
std::string test_614 = R"(Signed())";
std::string test_615 = R"(
    ``class Snapshot`` is a model of an individual database snapshot, created on save.
    )";
std::string test_616 = R"(StackFrameOffsetRegisterValue(value: int, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.StackFrameOffset: 5>, confidence: int = 255, size: int = 0))";
std::string test_617 = R"(StackOperation())";
std::string test_618 = R"(StackVariableReference(_source_operand: Optional[int], type: 'binaryninja.types.Type', name: str, var: 'Variable', referenced_offset: int, size: int))";
std::string test_619 = R"(Store())";
std::string test_620 = R"(An enumeration.)";
std::string test_621 = R"(StructureMember(type: 'Type', name: str, offset: int, access: binaryninja.enums.MemberAccess = <MemberAccess.NoAccess: 0>, scope: binaryninja.enums.MemberScope = <MemberScope.NoScope: 0>))";
std::string test_622 = R"(An enumeration.)";
std::string test_623 = R"(StructuredDataValue(t: '_type.Type', addr: int, val: bytes, e: binaryninja.enums.Endianness))";
std::string test_624 = R"(
		``class StructuredDataView`` is a convenience class for reading structured binary data.

		StructuredDataView can be instantiated as follows::
			>>> from binaryninja import *
			>>> bv = load("/bin/ls")
			>>> structure = "Elf64_Header"
			>>> address = bv.start
			>>> elf = StructuredDataView(bv, structure, address)
			>>>

		Once instantiated, members can be accessed::
			>>> print("{:x}".format(elf.machine))
			003e
			>>>

		)";
std::string test_625 = R"(
	Symbols are defined as one of the following types:

		=========================== =================================================================
		SymbolType                  Description
		=========================== =================================================================
		FunctionSymbol              Symbol for function that exists in the current binary
		ImportAddressSymbol         Symbol defined in the Import Address Table
		ImportedFunctionSymbol      Symbol for a function that is not defined in the current binary
		DataSymbol                  Symbol for data in the current binary
		ImportedDataSymbol          Symbol for data that is not defined in the current binary
		ExternalSymbol              Symbols for data and code that reside outside the BinaryView
		LibraryFunctionSymbol       Symbols for functions identified as belonging to a shared library
		=========================== =================================================================
	)";
std::string test_626 = R"(An enumeration.)";
std::string test_627 = R"(
	SymbolMapping object is used to improve performance of the `bv.symbols` API.
	This allows pythonic code like this to have reasonable performance characteristics

		>>> my_symbols = get_my_symbols()
		>>> for symbol in my_symbols:
		>>>  if bv.symbols[symbol].address == 0x41414141:
		>>>    print("Found")

	)";
std::string test_628 = R"(An enumeration.)";
std::string test_629 = R"(Syscall())";
std::string test_630 = R"(
	The ``Tag`` object is created by other APIs (create_*_tag) and should not be directly instantiated.
	)";
std::string test_631 = R"(An enumeration.)";
std::string test_632 = R"(
	The ``TagType`` object is created by the create_tag_type API and should not be directly instantiated.
	)";
std::string test_633 = R"(An enumeration.)";
std::string test_634 = R"(Tailcall())";
std::string test_635 = R"(Terminal())";
std::string test_636 = R"(
	``TextLineField`` Adds prompt for text string input. Result is stored in self.result as a string on completion.
	)";
std::string test_637 = R"(An enumeration.)";
std::string test_638 = R"(An enumeration.)";
std::string test_639 = R"(
	``class Transform`` allows users to implement custom transformations. New transformations may be added at runtime,
	so an instance of a transform is created like::

		>>> list(Transform)
		[<transform: Zlib>, <transform: StringEscape>, <transform: RawHex>, <transform: HexDump>, <transform: Base64>, <transform: Reverse>, <transform: CArray08>, <transform: CArrayA16>, <transform: CArrayA32>, <transform: CArrayA64>, <transform: CArrayB16>, <transform: CArrayB32>, <transform: CArrayB64>, <transform: IntList08>, <transform: IntListA16>, <transform: IntListA32>, <transform: IntListA64>, <transform: IntListB16>, <transform: IntListB32>, <transform: IntListB64>, <transform: MD4>, <transform: MD5>, <transform: SHA1>, <transform: SHA224>, <transform: SHA256>, <transform: SHA384>, <transform: SHA512>, <transform: AES-128 ECB>, <transform: AES-128 CBC>, <transform: AES-256 ECB>, <transform: AES-256 CBC>, <transform: DES ECB>, <transform: DES CBC>, <transform: Triple DES ECB>, <transform: Triple DES CBC>, <transform: RC2 ECB>, <transform: RC2 CBC>, <transform: Blowfish ECB>, <transform: Blowfish CBC>, <transform: CAST ECB>, <transform: CAST CBC>, <transform: RC4>, <transform: XOR>]
		>>> sha512=Transform['SHA512']
		>>> rawhex=Transform['RawHex']
		>>> rawhex.encode(sha512.encode("test string"))
		'10e6d647af44624442f388c2c14a787ff8b17e6165b83d767ec047768d8cbcb71a1a3226e7cc7816bc79c0427d94a9da688c41a3992c7bf5e4d7cc3e0be5dbac'

	Note that some transformations take additional parameters (most notably encryption ones that require a 'key' parameter passed via a dict):

		>>> xor=Transform['XOR']
		>>> rawhex=Transform['RawHex']
		>>> xor.encode("Original Data", {'key':'XORKEY'})
		>>> rawhex.encode(xor.encode("Original Data", {'key':'XORKEY'}))
		b'173d3b2c2c373923720f242d39'
	)";
std::string test_640 = R"(An enumeration.)";
std::string test_641 = R"(
	``class Type`` allows you to interact with the Binary Ninja type system. Note that the ``repr`` and ``str``
	handlers respond differently on type objects.

	Other related functions that may be helpful include:

	:py:meth:`parse_type_string <binaryview.BinaryView.parse_type_string>`
	:py:meth:`parse_types_from_source <platform.Platform.parse_types_from_source>`
	:py:meth:`parse_types_from_source_file <platform.Platform.parse_types_from_source_file>`

	)";
std::string test_642 = R"(
	All TypeBuilder objects should not be instantiated directly but created via ``.create`` APIs.
	)";
std::string test_643 = R"(An enumeration.)";
std::string test_644 = R"(TypeDefinitionLine(line_type: binaryninja.enums.TypeDefinitionLineType, tokens: List[ForwardRef('_function.InstructionTextToken')], type: 'Type', root_type: 'Type', root_type_name: str, base_type: Optional[ForwardRef('NamedTypeReferenceType')], base_offset: int, offset: int, field_index: int))";
std::string test_645 = R"(An enumeration.)";
std::string test_646 = R"(TypeFieldReference(func: Optional[ForwardRef('_function.Function')], arch: Optional[ForwardRef('architecture.Architecture')], address: int, size: int, incomingType: Optional[binaryninja.types.Type]))";
std::string test_647 = R"(
	TypeMapping object is used to improve performance of the `bv.types` API.
	This allows pythonic code like this to have reasonable performance characteristics

		>>> my_types = get_my_types()
		>>> for type_name in my_types:
		>>>  if bv.types[type_name].width == 4:
		>>>    print("Found")

	)";
std::string test_648 = R"(TypeParserError(severity: binaryninja.enums.TypeParserErrorSeverity, message: str, file_name: str, line: int, column: int))";
std::string test_649 = R"(An enumeration.)";
std::string test_650 = R"(An enumeration.)";
std::string test_651 = R"(TypeParserResult(types: List[binaryninja.typeparser.ParsedType], variables: List[binaryninja.typeparser.ParsedType], functions: List[binaryninja.typeparser.ParsedType]))";
std::string test_652 = R"(
	Class for turning Type objects into strings and tokens.
	)";
std::string test_653 = R"(TypeReferenceSource(name: binaryninja.types.QualifiedName, offset: int, ref_type: binaryninja.enums.TypeReferenceType))";
std::string test_654 = R"(An enumeration.)";
std::string test_655 = R"(Type variable.

    Usage::

      T = TypeVar('T')  # Can be anything
      A = TypeVar('A', str, bytes)  # Must be str or bytes

    Type variables exist primarily for the benefit of static type
    checkers.  They serve as the parameters for generic types as well
    as for generic function definitions.  See class Generic for more
    information on generic types.  Generic functions work as follows:

      def repeat(x: T, n: int) -> List[T]:
          '''Return a list containing n references to x.'''
          return [x]*n

      def longest(x: A, y: A) -> A:
          '''Return the longest of two strings.'''
          return x if len(x) >= len(y) else y

    The latter example's signature is essentially the overloading
    of (str, str) -> str and (bytes, bytes) -> bytes.  Also note
    that if the arguments are instances of some subclass of str,
    the return type is still plain str.

    At runtime, isinstance(x, T) and issubclass(C, T) will raise TypeError.

    Type variables defined with covariant=True or contravariant=True
    can be used to declare covariant or contravariant generic types.
    See PEP 484 for more details. By default generic types are invariant
    in all type variables.

    Type variables can be introspected. e.g.:

      T.__name__ == 'T'
      T.__constraints__ == ()
      T.__covariant__ == False
      T.__contravariant__ = False
      A.__constraints__ == (str, bytes)

    Note that only type variables defined in global scope can be pickled.
    )";
std::string test_656 = R"(TypedDataAccessor(type: '_types.Type', address: int, view: 'BinaryView', endian: binaryninja.enums.Endianness))";
std::string test_657 = R"(TypedDataAccessor(type: '_types.Type', address: int, view: 'BinaryView', endian: binaryninja.enums.Endianness))";
std::string test_658 = R"(UnaryOperation())";
std::string test_659 = R"(Undetermined(value: int = 0, offset: int = 0, type: binaryninja.enums.RegisterValueType = <RegisterValueType.UndeterminedValue: 0>, confidence: int = 255, size: int = 0))";
std::string test_660 = R"(A warning class for methods to be removed

    This is a subclass of :class:`~deprecation.DeprecatedWarning` and is used
    to output a proper message about a function being unsupported.
    Additionally, the :func:`~deprecation.fail_if_not_removed` decorator
    will handle this warning and cause any tests to fail if the system
    under test uses code that raises this warning.
    )";
std::string test_661 = R"(An enumeration.)";
std::string test_662 = R"(ValueRange(start: int, end: int, step: int))";
std::string test_663 = R"(VariableInstruction())";
std::string test_664 = R"(VariableNameAndType(_source_type: int, index: int, storage: int, name: str, type: 'binaryninja.types.Type'))";
std::string test_665 = R"(VariableReferenceSource(var: 'variable.Variable', src: binaryninja.function.ILReferenceSource))";
std::string test_666 = R"(An enumeration.)";
std::string test_667 = R"(An enumeration.)";
std::string test_668 = R"(str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to sys.getdefaultencoding().
errors defaults to 'strict'.)";
std::string test_669 = R"(
	:class:`Workflow` A Binary Ninja Workflow is an abstraction of a computational binary analysis pipeline and it provides the extensibility 	mechanism needed for tailored binary analysis and decompilation. More specifically, a Workflow is a repository of activities along with a 	unique strategy to execute them. Binary Ninja provides two Workflows named ``core.module.defaultAnalysis`` and ``core.function.defaultAnalysis`` 	which expose the core analysis.

	A Workflow starts in the unregistered state from either creating a new empty Workflow, or cloning an existing Workflow. While unregistered 	it's possible to add and remove activities, as well as change the execution strategy. In order to use the Workflow on a binary it must be 	registered. Once registered the Workflow is immutable and available for use.

	Currently, Workflows is disabled by default and can be enabled via Settings::

		>>> Settings().set_bool('workflows.enable', True)

	Retrieve the default Workflow by creating a Workflow object::

		>>> Workflow()
		<Workflow: core.module.defaultAnalysis>

	Retrieve any registered Workflow by name::

		>>> list(Workflow)
		[<Workflow: core.function.defaultAnalysis>, <Workflow: core.module.defaultAnalysis>]
		>>> Workflow('core.module.defaultAnalysis')
		<Workflow: core.module.defaultAnalysis>
		>>> Workflow('core.function.defaultAnalysis')
		<Workflow: core.function.defaultAnalysis>

	Create a new Workflow, show it in the UI, modify and then register it. Try it via Open with Options and selecting the new Workflow::

		>>> pwf = Workflow().clone("PythonLogWarnWorkflow")
		>>> pwf.show_topology()
		>>> pwf.register_activity(Activity("PythonLogWarn", action=lambda analysis_context: log_warn("PythonLogWarn Called!")))
		>>> pwf.insert("core.function.basicBlockAnalysis", ["PythonLogWarn"])
		>>> pwf.register()

	.. note:: Binary Ninja Workflows is currently under development and available as an early feature preview. For additional documentation see Help / User Guide / Developer Guide / Workflows

	)";
std::string test_670 = R"(Abstract Base Classes (ABCs) according to PEP 3119.)";
std::string test_671 = R"(
Function deprecated. Use update_license instead.

Check out and activate a license from the Enterprise Server.

.. note:: You must authenticate with the Enterprise Server before calling this.

:param int duration: Desired length of license checkout, in seconds.
:param bool _cache: Deprecated but left in for compatibility


.. deprecated:: 3.4.4137 Use .update_license instead.)";
std::string test_672 = R"(
	``are_auto_updates_enabled`` queries if auto updates are enabled.

	:return: boolean True if auto updates are enabled. False if they are disabled.
	:rtype: bool
	)";
std::string test_673 = R"(Command-line parsing library

This module is an optparse-inspired command-line parsing library that:

    - handles both optional and positional arguments
    - produces highly informative usage messages
    - supports parsers that dispatch to sub-parsers

The following is a simple usage example that sums integers from the
command-line and writes the result to a file::

    parser = argparse.ArgumentParser(
        description='sum the integers at the command line')
    parser.add_argument(
        'integers', metavar='int', nargs='+', type=int,
        help='an integer to be summed')
    parser.add_argument(
        '--log', default=sys.stdout, type=argparse.FileType('w'),
        help='the file where the sum should be written')
    args = parser.parse_args()
    args.log.write('%s' % sum(args.integers))
    args.log.close()

The module contains the following public classes:

    - ArgumentParser -- The main entry point for command-line parsing. As the
        example above shows, the add_argument() method is used to populate
        the parser with actions for optional and positional arguments. Then
        the parse_args() method is invoked to convert the args at the
        command-line into an object with attributes.

    - ArgumentError -- The exception raised by ArgumentParser objects when
        there are errors with the parser's actions. Errors raised while
        parsing the command-line are caught by ArgumentParser and emitted
        as command-line messages.

    - FileType -- A factory for defining types of files to be created. As the
        example above shows, instances of FileType are typically passed as
        the type= argument of add_argument() calls.

    - Action -- The base class for parser actions. Typically actions are
        selected by passing strings like 'store_true' or 'append_const' to
        the action= argument of add_argument(). However, for greater
        customization of ArgumentParser actions, subclasses of Action may
        be defined and passed as the action= argument.

    - HelpFormatter, RawDescriptionHelpFormatter, RawTextHelpFormatter,
        ArgumentDefaultsHelpFormatter -- Formatter classes which
        may be passed as the formatter_class= argument to the
        ArgumentParser constructor. HelpFormatter is the default,
        RawDescriptionHelpFormatter and RawTextHelpFormatter tell the parser
        not to change the formatting for help text, and
        ArgumentDefaultsHelpFormatter adds information about argument defaults
        to the help.

All other classes in this module are considered implementation details.
(Also note that HelpFormatter and RawDescriptionHelpFormatter are only
considered public as object names -- the API of the formatter objects is
still considered an implementation detail.)
)";
std::string test_674 = R"(allow programmer to define multiple exit functions to be executed
upon normal program termination.

Two public functions, register and unregister, are defined.
)";
std::string test_675 = R"(
	Authenticate to the Enterprise Server with username/password credentials.

	:param str username: Username to use.
	:param str password: Password to use.
	:param bool remember: Remember token in keychain
	)";
std::string test_676 = R"(
	Authenticate to the Enterprise Server with a non-password method. Note that many of these will
	open a URL for a browser-based login prompt, which may not be usable on headless installations.
	See :func:`authentication_methods` for a list of accepted methods.

	:param str method: Name of method to use.
	:param bool remember: Remember token in keychain
	)";
std::string test_677 = R"(
	Get a list of authentication methods accepted by the Enterprise Server.

	:return: List of (<method name>, <method display name>) tuples
	)";
std::string test_678 = R"( This file is a modified version of rlcompleter.py from the Python
project under the Python Software Foundation License 2:
https://github.com/python/cpython/blob/master/Lib/rlcompleter.py
https://github.com/python/cpython/blob/master/LICENSE

The only changes made were to modify the regular expression in attr_matches
and all code that relied on GNU readline (the later more for readability as
it wasn't required).

--------------

Word completion for GNU readline.

The completer completes keywords, built-ins and globals in a selectable
namespace (which defaults to __main__); when completing NAME.NAME..., it
evaluates (!) the expression up to the last dot and completes its attributes.

It's very cool to do "import sys" type "sys.", hit the completion key (twice),
and see the list of names defined by the sys module!

Tip: to use the tab key as the completion key, call

	readline.parse_and_bind("tab: complete")

Notes:

- Exceptions raised by the completer function are *ignored* (and generally cause
  the completion to fail).  This is a feature -- since readline sets the tty
  device in raw (or cbreak) mode, printing a traceback wouldn't work well
  without some complicated hoopla to save, reset and restore the tty state.

- The evaluation of the NAME.NAME... form may cause arbitrary application
  defined code to be executed if an object with a __getattr__ hook is found.
  Since it is the responsibility of the application (or the user) to enable this
  feature, I consider this an acceptable risk.  More complicated expressions
  (e.g. function calls or indexing operations) are *not* evaluated.

- When the original stdin is not a tty device, GNU readline is never
  used, and this module (and the readline module) are silently inactive.

)";
std::string test_679 = R"(
	``bninspect`` prints documentation about a command that is about to be run
	The interpreter will invoke this function if you input a line ending in `?` e.g. `bv?`

	:param str code_: Python code to be evaluated
	:param dict globals_: globals() from callsite
	:param dict locals_: locals() from callsite
	)";
std::string test_680 = R"(
		``bundled_plugin_path`` returns a string containing the current plugin path inside the `install path <https://docs.binary.ninja/guide/#binary-path>`_

		:return: current bundled plugin path
		:rtype: str, or None on failure
	)";
std::string test_681 = R"(
	Cancel a call to :func:`authenticate_with_credentials` or :func:`authenticate_with_method`.
	Note those functions are blocking, so this must be called on a separate thread.
	)";
std::string test_682 = R"(
	``close_logs`` close all log files.

	:rtype: None
	)";
std::string test_683 = R"(A generic class to build line-oriented command interpreters.

Interpreters constructed with this class obey the following conventions:

1. End of file on input is processed as the command 'EOF'.
2. A command is parsed out of each line by collecting the prefix composed
   of characters in the identchars member.
3. A command `foo' is dispatched to a method 'do_foo()'; the do_ method
   is passed a single argument consisting of the remainder of the line.
4. Typing an empty line repeats the last command.  (Actually, it calls the
   method `emptyline', which may be overridden in a subclass.)
5. There is a predefined `help' method.  Given an argument `topic', it
   calls the command `help_topic'.  With no arguments, it lists all topics
   with defined help_ functions, broken into up to three topics; documented
   commands, miscellaneous help topics, and undocumented commands.
6. The command '?' is a synonym for `help'.  The command '!' is a synonym
   for `shell', if a do_shell method exists.
7. If completion is enabled, completing commands will be done automatically,
   and completing of commands args is done by calling complete_foo() with
   arguments text, line, begidx, endidx.  text is string we are matching
   against, all returned matches must begin with it.  line is the current
   input line (lstripped), begidx and endidx are the beginning and end
   indexes of the text being matched, which could be used to provide
   different completion depending upon which position the argument is in.

The `default' method may be overridden to intercept commands for which there
is no do_ method.

The `completedefault' method may be overridden to intercept completions for
commands that have no complete_ method.

The data member `self.ruler' sets the character used to draw separator lines
in the help messages.  If empty, no ruler line is drawn.  It defaults to "=".

If the value of `self.intro' is nonempty when the cmdloop method is called,
it is printed out on interpreter startup.  This value may be overridden
via an optional argument to the cmdloop() method.

The data members `self.doc_header', `self.misc_header', and
`self.undoc_header' set the headers used for the help function's
listings of documented functions, miscellaneous topics, and undocumented
functions respectively.
)";
std::string test_684 = R"(Utilities needed to emulate Python's interactive interpreter.

)";
std::string test_685 = R"(This module implements specialized container datatypes providing
alternatives to Python's general purpose built-in containers, dict,
list, set, and tuple.

* namedtuple   factory function for creating tuple subclasses with named fields
* deque        list-like container with fast appends and pops on either end
* ChainMap     dict-like class for creating a single view of multiple mappings
* Counter      dict subclass for counting hashable objects
* OrderedDict  dict subclass that remembers the order entries were added
* defaultdict  dict subclass that calls a factory function to supply missing values
* UserDict     wrapper around dictionary objects for easier dict subclassing
* UserList     wrapper around list objects for easier list subclassing
* UserString   wrapper around string objects for easier string subclassing

)";
std::string test_686 = R"(
	Connect to the Enterprise Server.
	)";
std::string test_687 = R"(
	Connect to PyCharm (Professional Edition) for debugging.

	.. note:: See https://docs.binary.ninja/dev/plugins.html#remote-debugging-with-intellij-pycharm for step-by-step instructions on how to set up Python debugging.

	:param port: Port number for connecting to the debugger.
	)";
std::string test_688 = R"(
	Connect to Visual Studio Code for debugging. This function blocks until the debugger
	is connected! Not recommended for use in startup.py

	.. note:: See https://docs.binary.ninja/dev/plugins.html#remote-debugging-with-vscode for step-by-step instructions on how to set up Python debugging.

	:param port: Port number for connecting to the debugger.
	)";
std::string test_689 = R"(Utilities for with-statement contexts.  See PEP 343.)";
std::string test_690 = R"(
		``core_build_id`` returns a integer containing the current build id

		:return: current build id
		:rtype: int
	)";
std::string test_691 = R"(License Expiration)";
std::string test_692 = R"(License count from the license file)";
std::string test_693 = R"(Product string from the license file)";
std::string test_694 = R"(Product type from the license file)";
std::string test_695 = R"(
		``core_serial`` returns a string containing the current serial number

		:return: current serial
		:rtype: str, or None on failure
	)";
std::string test_696 = R"(
		``core_set_license`` is used to initialize the core with a license file that doesn't necessarily reside on a file system. This is especially useful for headless environments such as docker where loading the license file via an environment variable allows for greater security of the license file itself.

		:param str licenseData: string containing the full contents of a license file
		:rtype: None
		:Example:

			>>> import os
			>>> core_set_license(os.environ['BNLICENSE']) #Do this before creating any BinaryViews
			>>> with load("/bin/ls") as bv:
			...		print(len(list(bv.functions)))
			128
	)";
std::string test_697 = R"(Indicates that a UI exists and the UI has invoked BNInitUI)";
std::string test_698 = R"(
		``core_version`` returns a string containing the current version

		:return: current version
		:rtype: str, or None on failure
	)";
std::string test_699 = R"(
		``core_version_info`` returns a CoreVersionInfo containing the current version information

		:return: current version information
		:rtype: CoreVersionInfo
	)";
std::string test_700 = R"(create and manipulate C data types in Python)";
std::string test_701 = R"(Returns the same class as was passed in, with dunder methods
    added based on the fields defined in the class.

    Examines PEP 526 __annotations__ to determine fields.

    If init is true, an __init__() method is added to the class. If
    repr is true, a __repr__() method is added. If order is true, rich
    comparison dunder methods are added. If unsafe_hash is true, a
    __hash__() method function is added. If frozen is true, fields may
    not be assigned to after instance creation. If match_args is true,
    the __match_args__ tuple is added. If kw_only is true, then by
    default all fields are keyword-only. If slots is true, an
    __slots__ attribute is added.
    )";
std::string test_702 = R"(date(year, month, day) --> date object)";
std::string test_703 = R"(datetime(year, month, day[, hour[, minute[, second[, microsecond[,tzinfo]]]]])

The year, month and day arguments are required. tzinfo may be None, or an
instance of a tzinfo subclass. The remaining arguments may be ints.
)";
std::string test_704 = R"(
	Deauthenticate from the Enterprise server, clearing any cached credentials.
	)";
std::string test_705 = R"(defaultdict(default_factory=None, /, [...]) --> dict with default factory

The default factory is called without arguments to produce
a new value when a key is not present, in __getitem__ only.
A defaultdict compares equal to a dict with the same items.
All remaining arguments are treated the same as if they were
passed to the dict constructor, including keyword arguments.
)";
std::string test_706 = R"(
	``demangle_gnu3`` demangles a mangled name to a Type object.

	:param Architecture arch: Architecture for the symbol. Required for pointer and integer sizes.
	:param str mangled_name: a mangled GNU3 name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Tuple[bool, BinaryView, None]
	:return: returns tuple of (Type, demangled_name) or (None, mangled_name) on error
	:rtype: Tuple
	)";
std::string test_707 = R"(
	``demangle_ms`` demangles a mangled Microsoft Visual Studio C++ name to a Type object.

	:param Union[Architecture, Platform] archOrPlatform: Architecture or Platform for the symbol. Required for pointer/integer sizes and calling conventions.
	:param str mangled_name: a mangled Microsoft Visual Studio C++ name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Tuple[bool, BinaryView, None]
	:return: returns tuple of (Type, demangled_name) or (None, mangled_name) on error
	:rtype: Tuple
	:Example:

		>>> demangle_ms(Platform["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		(<type: public: static enum Foobar::foo __cdecl (enum Foobar::foo)>, ['Foobar', 'testf'])
		>>>
	)";
std::string test_708 = R"(Decorate a function to signify its deprecation

    This function wraps a method that will soon be removed and does two things:

        * The docstring of the method will be modified to include a notice
          about deprecation, e.g., "Deprecated since 0.9.11. Use foo instead."
        * Raises a :class:`~deprecation.DeprecatedWarning`
          via the :mod:`warnings` module, which is a subclass of the built-in
          :class:`DeprecationWarning`. Note that built-in
          :class:`DeprecationWarning` are ignored by default, so for users
          to be informed of said warnings they will need to enable them--see
          the :mod:`warnings` module documentation for more details.

    :param deprecated_in: The version at which the decorated method is
                          considered deprecated. This will usually be the
                          next version to be released when the decorator is
                          added.
    :param removed_in: The version or :class:`datetime.date` when the decorated
                       method will be removed. The default is **None**,
                       specifying that the function is not currently planned
                       to be removed.
    :param current_version: The source of version information for the
                            currently running code. This will usually be
                            a `__version__` attribute on your library.
                            The default is `None`.
                            When `current_version=None` the automation to
                            determine if the wrapped function is actually
                            in a period of deprecation or time for removal
                            does not work, causing a
                            :class:`~deprecation.DeprecatedWarning`
                            to be raised in all cases.
    :param details: Extra details to be added to the method docstring and
                    warning. For example, the details may point users to
                    a replacement method, such as "Use the foo_bar
                    method instead". By default there are no details.
    )";
std::string test_709 = R"(deque([iterable[, maxlen]]) --> deque object

A list-like sequence optimized for data accesses near its endpoints.)";
std::string test_710 = R"(Disable default logging in headless mode for the current session. By default, logging in headless operation is controlled by the 'python.log.minLevel' settings.)";
std::string test_711 = R"(Serialize ``obj`` to a JSON formatted ``str``.

    If ``skipkeys`` is true then ``dict`` keys that are not basic types
    (``str``, ``int``, ``float``, ``bool``, ``None``) will be skipped
    instead of raising a ``TypeError``.

    If ``ensure_ascii`` is false, then the return value can contain non-ASCII
    characters if they appear in strings contained in ``obj``. Otherwise, all
    such characters are escaped in JSON strings.

    If ``check_circular`` is false, then the circular reference check
    for container types will be skipped and a circular reference will
    result in an ``RecursionError`` (or worse).

    If ``allow_nan`` is false, then it will be a ``ValueError`` to
    serialize out of range ``float`` values (``nan``, ``inf``, ``-inf``) in
    strict compliance of the JSON specification, instead of using the
    JavaScript equivalents (``NaN``, ``Infinity``, ``-Infinity``).

    If ``indent`` is a non-negative integer, then JSON array elements and
    object members will be pretty-printed with that indent level. An indent
    level of 0 will only insert newlines. ``None`` is the most compact
    representation.

    If specified, ``separators`` should be an ``(item_separator, key_separator)``
    tuple.  The default is ``(', ', ': ')`` if *indent* is ``None`` and
    ``(',', ': ')`` otherwise.  To get the most compact JSON representation,
    you should specify ``(',', ':')`` to eliminate whitespace.

    ``default(obj)`` is a function that should return a serializable version
    of obj or raise TypeError. The default simply raises TypeError.

    If *sort_keys* is true (default: ``False``), then the output of
    dictionaries will be sorted by key.

    To use a custom ``JSONEncoder`` subclass (e.g. one that overrides the
    ``.default()`` method to serialize additional types), specify it with
    the ``cls`` kwarg; otherwise ``JSONEncoder`` is used.

    )";
std::string test_712 = R"(
.. note: This module is only available in the Enterprise edition of Binary Ninja.
)";
std::string test_713 = R"(Decorate a test method to track removal of deprecated code

    This decorator catches :class:`~deprecation.UnsupportedWarning`
    warnings that occur during testing and causes unittests to fail,
    making it easier to keep track of when code should be removed.

    :raises: :class:`AssertionError` if an
             :class:`~deprecation.UnsupportedWarning`
             is raised while running the test method.
    )";
std::string test_714 = R"(Return an object to identify dataclass fields.

    default is the default value of the field.  default_factory is a
    0-argument function called to initialize a field's value.  If init
    is true, the field will be a parameter to the class's __init__()
    function.  If repr is true, the field will be included in the
    object's repr().  If hash is true, the field will be included in the
    object's hash().  If compare is true, the field will be used in
    comparison functions.  metadata, if specified, must be a mapping
    which is stored but not otherwise examined by dataclass.  If kw_only
    is true, the field will become a keyword-only parameter to
    __init__().

    It is an error to specify both default and default_factory.
    )";
std::string test_715 = R"(
	``get_address_input`` prompts the user for an address with the given prompt and title

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:rtype: integer value input by the user.
	:Example:
		>>> get_address_input("PROMPT>", "getinfo")
		PROMPT> 10
		10L
	)";
std::string test_716 = R"(
	``get_choice_input`` prompts the user to select the one of the provided choices

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used. The UI uses a combo box.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:param choices: A list of strings for the user to choose from.
	:type choices: list(str)
	:rtype: integer array index of the selected option
	:Example:
		>>> get_choice_input("PROMPT>", "choices", ["Yes", "No", "Maybe"])
		choices
		1) Yes
		2) No
		3) Maybe
		PROMPT> 1
		0L
	)";
std::string test_717 = R"(
	``get_directory_name_input`` prompts the user for a directory name to save as, optionally providing a default_name

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line a simple text prompt is used. The UI uses the native window pop-up for file selection.

	:param str prompt: Prompt to display.
	:param str default_name: Optional, default directory name.
	:rtype: str
	:Example:
		>>> get_directory_name_input("prompt")
		prompt dirname
		'dirname'
	)";
std::string test_718 = R"(
	``get_from_input`` Prompts the user for a set of inputs specified in ``fields`` with given title. 	The fields parameter is a list which can contain the following types:

	===================== ===================================================
	FieldType             Description
	===================== ===================================================
	str                   an alias for LabelField
	None                  an alias for SeparatorField
	LabelField            Text output
	SeparatorField        Vertical spacing
	TextLineField         Prompt for a string value
	MultilineTextField    Prompt for multi-line string value
	IntegerField          Prompt for an integer
	AddressField          Prompt for an address
	ChoiceField           Prompt for a choice from provided options
	OpenFileNameField     Prompt for file to open
	SaveFileNameField     Prompt for file to save to
	DirectoryNameField    Prompt for directory name
	===================== ===================================================

	This API is flexible and works both in the UI via a pop-up dialog and on the command-line.

	.. note:: More complicated APIs should consider using the included pyside2 functionality in the `binaryninjaui` module. Returns true or false depending on whether the user submitted responses or cancelled the dialog.

	:param fields: A list containing these classes, strings or None
	:type fields: list(str) or list(None) or list(LabelField) or list(SeparatorField) or list(TextLineField) or list(MultilineTextField) or list(IntegerField) or list(AddressField) or list(ChoiceField) or list(OpenFileNameField) or list(SaveFileNameField) or list(DirectoryNameField)
	:param str title: The title of the pop-up dialog
	:rtype: bool
	:Example:

		>>> int_f = IntegerField("Specify Integer")
		>>> tex_f = TextLineField("Specify name")
		>>> choice_f = ChoiceField("Options", ["Yes", "No", "Maybe"])
		>>> get_form_input(["Get Data", None, int_f, tex_f, choice_f], "The options")
		Get Data
		<empty>
		Specify Integer 1337
		Specify name Peter
		The options
		1) Yes
		2) No
		3) Maybe
		Options 1
		>>> True
		>>> print(tex_f.result, int_f.result, choice_f.result)
		Peter 1337 0
	)";
std::string test_719 = R"(
	``get_install_directory`` returns a string pointing to the installed binary currently running

	.. warning:: ONLY for use within the Binary Ninja UI, behavior is undefined and unreliable if run headlessly
	)";
std::string test_720 = R"(
	``get_int_input`` prompts the user to input a integer with the given prompt and title

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:rtype: integer value input by the user.
	:Example:
		>>> get_int_input("PROMPT>", "getinfo")
		PROMPT> 10
		10
	)";
std::string test_721 = R"-(
	``get_open_filename_input`` prompts the user for a file name to open

	.. note:: This API functions differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used. The UI uses the native window pop-up for file selection.

	Multiple file selection groups can be included if separated by two semicolons. Multiple file wildcards may be specified by using a space within the parenthesis.

	Also, a simple selector of `*.extension` by itself may also be used instead of specifying the description.

	:param str prompt: Prompt to display.
	:param str ext: Optional, file extension
	:Example:
		>>> get_open_filename_input("filename:", "Executables (*.exe *.com);;Python Files (*.py);;All Files (*)";)
		'foo.exe'
		>>> get_open_filename_input("filename:", "*.py")
		'test.py'
	)-";
std::string test_722 = R"(
	``get_qualified_name`` gets a qualified name for the provided name list.

	:param names: name list to qualify
	:type names: list(str)
	:return: a qualified name
	:rtype: str
	:Example:

		>>> type, name = demangle_ms(Architecture["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		>>> get_qualified_name(name)
		'Foobar::testf'
		>>>
	)";
std::string test_723 = R"(
	``get_save_filename_input`` prompts the user for a file name to save as, optionally providing a file extension and 	default_name

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used. The UI uses the native window pop-up for file selection.

	:param str prompt: Prompt to display.
	:param str ext: Optional, file extension
	:param str default_name: Optional, default file name.
	:Example:
		>>> get_save_filename_input("filename:", "exe", "foo.exe")
		filename: foo.exe
		'foo.exe'
	)";
std::string test_724 = R"(
	``get_text_line_input`` prompts the user to input a string with the given prompt and title

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used.

	:param str prompt: String to prompt with.
	:param str title: Title of the window when executed in the UI.
	:rtype: str containing the input without trailing newline character.
	:Example:
		>>> get_text_line_input("PROMPT>", "getinfo")
		PROMPT> Input!
		'Input!'
	)";
std::string test_725 = R"(
	``get_time_since_last_update_check`` returns the time stamp for the last time updates were checked.

	:return: time stamp for last update check
	:rtype: int
	)";
std::string test_726 = R"(A pure Python implementation of import.)";
std::string test_727 = R"(Get useful information from live Python objects.

This module encapsulates the interface provided by the internal special
attributes (co_*, im_*, tb_*, etc.) in a friendlier fashion.
It also provides some help for examining source code and class layout.

Here are some of the useful functions provided by this module:

    ismodule(), isclass(), ismethod(), isfunction(), isgeneratorfunction(),
        isgenerator(), istraceback(), isframe(), iscode(), isbuiltin(),
        isroutine() - check object types
    getmembers() - get members of an object that satisfy a given condition

    getfile(), getsourcefile(), getsource() - find an object's source code
    getdoc(), getcomments() - get documentation on an object
    getmodule() - determine the module that an object came from
    getclasstree() - arrange classes so as to represent their hierarchy

    getargvalues(), getcallargs() - get info about function arguments
    getfullargspec() - same, with support for Python 3 features
    formatargvalues() - format an argument spec
    getouterframes(), getinnerframes() - get info about frames
    currentframe() - get the current stack frame
    stack(), trace() - get info about frames on the stack or in a traceback

    signature() - get a Signature object for the callable

    get_annotations() - safely compute an object's annotations
)";
std::string test_728 = R"(
	``install_pending_update`` installs any pending updates

	:rtype: None
	)";
std::string test_729 = R"(
	Determine if you have authenticated to the Enterprise Server.

	:return: True if you are authenticated
	)";
std::string test_730 = R"(
	Determine if the Enterprise Server is currently connected.

	:return: True if connected
	)";
std::string test_731 = R"(
	Determine if a floating license is currently active

	:return: True if a floating license is active
	)";
std::string test_732 = R"(
	Determine if the Enterprise Client has been initialized yet.

	:return: True if any other Enterprise methods have been called
	)";
std::string test_733 = R"(
	Determine if your current license checkout is still valid.

	:return: True if your current checkout is still valid.
	)";
std::string test_734 = R"(
	``is_update_installation_pending`` whether an update has been downloaded and is waiting installation

	:return: boolean True if an update is pending, false if no update is pending
	:rtype: bool
	)";
std::string test_735 = R"(JSON (JavaScript Object Notation) <https://json.org> is a subset of
JavaScript syntax (ECMA-262 3rd edition) used as a lightweight data
interchange format.

:mod:`json` exposes an API familiar to users of the standard library
:mod:`marshal` and :mod:`pickle` modules.  It is derived from a
version of the externally maintained simplejson library.

Encoding basic Python object hierarchies::

    >>> import json
    >>> json.dumps(['foo', {'bar': ('baz', None, 1.0, 2)}])
    '["foo", {"bar": ["baz", null, 1.0, 2]}]'
    >>> print(json.dumps("\"foo\bar"))
    "\"foo\bar"
    >>> print(json.dumps('\u1234'))
    "\u1234"
    >>> print(json.dumps('\\'))
    "\\"
    >>> print(json.dumps({"c": 0, "b": 0, "a": 0}, sort_keys=True))
    {"a": 0, "b": 0, "c": 0}
    >>> from io import StringIO
    >>> io = StringIO()
    >>> json.dump(['streaming API'], io)
    >>> io.getvalue()
    '["streaming API"]'

Compact encoding::

    >>> import json
    >>> mydict = {'4': 5, '6': 7}
    >>> json.dumps([1,2,3,mydict], separators=(',', ':'))
    '[1,2,3,{"4":5,"6":7}]'

Pretty printing::

    >>> import json
    >>> print(json.dumps({'4': 5, '6': 7}, sort_keys=True, indent=4))
    {
        "4": 5,
        "6": 7
    }

Decoding JSON::

    >>> import json
    >>> obj = ['foo', {'bar': ['baz', None, 1.0, 2]}]
    >>> json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]') == obj
    True
    >>> json.loads('"\\"foo\\bar"') == '"foo\x08ar'
    True
    >>> from io import StringIO
    >>> io = StringIO('["streaming API"]')
    >>> json.load(io)[0] == 'streaming API'
    True

Specializing JSON object decoding::

    >>> import json
    >>> def as_complex(dct):
    ...     if '__complex__' in dct:
    ...         return complex(dct['real'], dct['imag'])
    ...     return dct
    ...
    >>> json.loads('{"__complex__": true, "real": 1, "imag": 2}',
    ...     object_hook=as_complex)
    (1+2j)
    >>> from decimal import Decimal
    >>> json.loads('1.1', parse_float=Decimal) == Decimal('1.1')
    True

Specializing JSON object encoding::

    >>> import json
    >>> def encode_complex(obj):
    ...     if isinstance(obj, complex):
    ...         return [obj.real, obj.imag]
    ...     raise TypeError(f'Object of type {obj.__class__.__name__} '
    ...                     f'is not JSON serializable')
    ...
    >>> json.dumps(2 + 1j, default=encode_complex)
    '[2.0, 1.0]'
    >>> json.JSONEncoder(default=encode_complex).encode(2 + 1j)
    '[2.0, 1.0]'
    >>> ''.join(json.JSONEncoder(default=encode_complex).iterencode(2 + 1j))
    '[2.0, 1.0]'


Using json.tool from the shell to validate and pretty-print::

    $ echo '{"json":"obj"}' | python -m json.tool
    {
        "json": "obj"
    }
    $ echo '{ 1.2:3.4}' | python -m json.tool
    Expecting property name enclosed in double quotes: line 1 column 3 (char 2)
)";
std::string test_736 = R"(
	Get a text representation the last error encountered by the Enterprise Client

	:return: Last error message, or empty string if there is none.
	)";
std::string test_737 = R"(
	Get the duration of the current license checkout.

	:return: Duration, in seconds, of the total time of the current checkout.
	)";
std::string test_738 = R"(
	Get the expiry time of the current license checkout.

	:return: Expiry time as a Unix epoch, or 0 if no license is checked out.
	)";
std::string test_739 = R"(
	Opens a BinaryView object.

	:param Union[str, bytes, bytearray, 'databuffer.DataBuffer', 'os.PathLike'] source: a file or byte stream to load into a virtual memory space
	:param bool update_analysis: whether or not to run :func:`update_analysis_and_wait` after opening a :py:class:`BinaryView`, defaults to ``True``
	:param callback progress_func: optional function to be called with the current progress and total count
	:param dict options: a dictionary in the form {setting identifier string : object value}
	:return: returns a :py:class:`BinaryView` object for the given filename
	:rtype: :py:class:`BinaryView`
	:raises Exception: When a BinaryView could not be created

	.. note:: The progress_func callback **must** return True to continue the load operation, False will abort the load operation.

	:Example:
		>>> from binaryninja import *
		>>> with load("/bin/ls") as bv:
		...     print(len(list(bv.functions)))
		...
		134

		>>> with load(bytes.fromhex('5054ebfe'), options={'loader.architecture' : 'x86'}) as bv:
		...     print(len(list(bv.functions)))
		...
		1
	)";
std::string test_740 = R"(Deserialize ``s`` (a ``str``, ``bytes`` or ``bytearray`` instance
    containing a JSON document) to a Python object.

    ``object_hook`` is an optional function that will be called with the
    result of any object literal decode (a ``dict``). The return value of
    ``object_hook`` will be used instead of the ``dict``. This feature
    can be used to implement custom decoders (e.g. JSON-RPC class hinting).

    ``object_pairs_hook`` is an optional function that will be called with the
    result of any object literal decoded with an ordered list of pairs.  The
    return value of ``object_pairs_hook`` will be used instead of the ``dict``.
    This feature can be used to implement custom decoders.  If ``object_hook``
    is also defined, the ``object_pairs_hook`` takes priority.

    ``parse_float``, if specified, will be called with the string
    of every JSON float to be decoded. By default this is equivalent to
    float(num_str). This can be used to use another datatype or parser
    for JSON floats (e.g. decimal.Decimal).

    ``parse_int``, if specified, will be called with the string
    of every JSON int to be decoded. By default this is equivalent to
    int(num_str). This can be used to use another datatype or parser
    for JSON integers (e.g. float).

    ``parse_constant``, if specified, will be called with one of the
    following strings: -Infinity, Infinity, NaN.
    This can be used to raise an exception if invalid JSON numbers
    are encountered.

    To use a custom ``JSONDecoder`` subclass, specify it with the ``cls``
    kwarg; otherwise ``JSONDecoder`` is used.
    )";
std::string test_741 = R"(
	``log_alert`` Logs message console and to a pop up window if run through the GUI.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_alert("Kielbasa!")
		Kielbasa!
		>>>
	)";
std::string test_742 = R"(
	``log`` writes messages to the log console for the given log level.

		============ ======== =======================================================================
		LogLevelName LogLevel  Description
		============ ======== =======================================================================
		DebugLog        0     Logs debugging information messages to the console.
		InfoLog         1     Logs general information messages to the console.
		WarningLog      2     Logs message to console with **Warning** icon.
		ErrorLog        3     Logs message to console with **Error** icon, focusing the error console.
		AlertLog        4     Logs message to pop up window.
		============ ======== =======================================================================

	:param LogLevel level: Log level to use
	:param str text: message to print
	:rtype: None
	)";
std::string test_743 = R"(
	``log_debug`` Logs debugging information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
	)";
std::string test_744 = R"(
	``log_error`` Logs message to console, if run through the GUI it logs with **Error** icon, focusing the error console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_error("Spanferkel!")
		Spanferkel!
		>>>
	)";
std::string test_745 = R"(
	``log_info`` Logs general information messages to the console.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_info("Saucisson!")
		Saucisson!
		>>>
	)";
std::string test_746 = R"(
	``log_to_file`` redirects minimum log level to a file named ``path``, optionally appending rather than overwriting.

	:param enums.Log_Level min_level: minimum level to log
	:param str path: path to log to
	:param bool append: optional flag for specifying appending. True = append, False = overwrite.
	:rtype: None
	)";
std::string test_747 = R"(
	``log_to_stderr`` redirects minimum log level to standard error.

	:param enums.LogLevel min_level: minimum level to log to
	:rtype: None
	)";
std::string test_748 = R"(
	``log_to_stdout`` redirects minimum log level to standard out.

	:param enums.LogLevel min_level: minimum level to log to
	:rtype: None
	:Example:

		>>> log_debug("Hotdogs!")
		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_debug("Hotdogs!")
		Hotdogs!
		>>>
	)";
std::string test_749 = R"(
	``log_warn`` Logs message to console, if run through the GUI it logs with **Warning** icon.

	:param str text: message to print
	:rtype: None
	:Example:

		>>> log_to_stdout(LogLevel.DebugLog)
		>>> log_warn("Chilidogs!")
		Chilidogs!
		>>>
	)";
std::string test_750 = R"(
	``markdown_to_html`` converts the provided markdown to HTML

	:param str contents: Markdown contents to convert to HTML
	:rtype: str
	:Example:
		>>> markdown_to_html("##Yay")
		'<h2>Yay</h2>'
	)";
std::string test_751 = R"(
	``open_url`` Opens a given url in the user's web browser, if available.

	:param str url: Url to open
	:return: True if successful
	:rtype: bool
	)";
std::string test_752 = R"(

.. deprecated:: 3.5.4378 Use :py:func:`BinaryView.load` instead)";
std::string test_753 = R"(OS routines for NT or Posix depending on what system we're on.

This exports:
  - all functions from posix or nt, e.g. unlink, stat, etc.
  - os.path is either posixpath or ntpath
  - os.name is either 'posix' or 'nt'
  - os.curdir is a string representing the current directory (always '.')
  - os.pardir is a string representing the parent directory (always '..')
  - os.sep is the (or a most common) pathname separator ('/' or '\\')
  - os.extsep is the extension separator (always '.')
  - os.altsep is the alternate pathname separator (None or '/')
  - os.pathsep is the component separator used in $PATH etc
  - os.linesep is the line separator in text files ('\r' or '\n' or '\r\n')
  - os.defpath is the default search path for executables
  - os.devnull is the file path of the null device ('/dev/null', etc.)

Programs that import and use 'os' stand a better chance of being
portable between different platforms.  Of course, they must then
only use functions that are defined by all platforms (e.g., unlink
and opendir), and leave all pathname manipulation to os.path
(e.g., split and join).
)";
std::string test_754 = R"(
``preprocess_source`` run the C preprocessor on the given source or source filename.

:param str source: source to pre-process
:param str filename: optional filename to pre-process
:param include_dirs: list of string directories to use as include directories.
:type include_dirs: list(str)
:return: returns a tuple of (preprocessed_source, error_string)
:rtype: tuple(str,str)
:Example:

	>>> source = "#define TEN 10\nint x[TEN];\n"
	>>> preprocess_source(source)
	('#line 1 "input"\n\n#line 2 "input"\n int x [ 10 ] ;\n', '')
	>>>


.. deprecated:: 3.4.4271 Use TypeParser.preprocess_source instead.)";
std::string test_755 = R"(A multi-producer, multi-consumer queue.)";
std::string test_756 = R"(Support for regular expressions (RE).

This module provides regular expression matching operations similar to
those found in Perl.  It supports both 8-bit and Unicode strings; both
the pattern and the strings being processed can contain null bytes and
characters outside the US ASCII range.

Regular expressions can contain both special and ordinary characters.
Most ordinary characters, like "A", "a", or "0", are the simplest
regular expressions; they simply match themselves.  You can
concatenate ordinary characters, so last matches the string 'last'.

The special characters are:
    "."      Matches any character except a newline.
    "^"      Matches the start of the string.
    "$"      Matches the end of the string or just before the newline at
             the end of the string.
    "*"      Matches 0 or more (greedy) repetitions of the preceding RE.
             Greedy means that it will match as many repetitions as possible.
    "+"      Matches 1 or more (greedy) repetitions of the preceding RE.
    "?"      Matches 0 or 1 (greedy) of the preceding RE.
    *?,+?,?? Non-greedy versions of the previous three special characters.
    {m,n}    Matches from m to n repetitions of the preceding RE.
    {m,n}?   Non-greedy version of the above.
    "\\"     Either escapes special characters or signals a special sequence.
    []       Indicates a set of characters.
             A "^" as the first character indicates a complementing set.
    "|"      A|B, creates an RE that will match either A or B.
    (...)    Matches the RE inside the parentheses.
             The contents can be retrieved or matched later in the string.
    (?aiLmsux) The letters set the corresponding flags defined below.
    (?:...)  Non-grouping version of regular parentheses.
    (?P<name>...) The substring matched by the group is accessible by name.
    (?P=name)     Matches the text matched earlier by the group named name.
    (?#...)  A comment; ignored.
    (?=...)  Matches if ... matches next, but doesn't consume the string.
    (?!...)  Matches if ... doesn't match next.
    (?<=...) Matches if preceded by ... (must be fixed length).
    (?<!...) Matches if not preceded by ... (must be fixed length).
    (?(id/name)yes|no) Matches yes pattern if the group with id/name matched,
                       the (optional) no pattern otherwise.

The special sequences consist of "\\" and a character from the list
below.  If the ordinary character is not on the list, then the
resulting RE will match the second character.
    \number  Matches the contents of the group of the same number.
    \A       Matches only at the start of the string.
    \Z       Matches only at the end of the string.
    \b       Matches the empty string, but only at the start or end of a word.
    \B       Matches the empty string, but not at the start or end of a word.
    \d       Matches any decimal digit; equivalent to the set [0-9] in
             bytes patterns or string patterns with the ASCII flag.
             In string patterns without the ASCII flag, it will match the whole
             range of Unicode digits.
    \D       Matches any non-digit character; equivalent to [^\d].
    \s       Matches any whitespace character; equivalent to [ \t\n\r\f\v] in
             bytes patterns or string patterns with the ASCII flag.
             In string patterns without the ASCII flag, it will match the whole
             range of Unicode whitespace characters.
    \S       Matches any non-whitespace character; equivalent to [^\s].
    \w       Matches any alphanumeric character; equivalent to [a-zA-Z0-9_]
             in bytes patterns or string patterns with the ASCII flag.
             In string patterns without the ASCII flag, it will match the
             range of Unicode alphanumeric characters (letters plus digits
             plus underscore).
             With LOCALE, it will match the set [0-9_] plus characters defined
             as letters for the current locale.
    \W       Matches the complement of \w.
    \\       Matches a literal backslash.

This module exports the following functions:
    match     Match a regular expression pattern to the beginning of a string.
    fullmatch Match a regular expression pattern to all of a string.
    search    Search a string for the presence of a pattern.
    sub       Substitute occurrences of a pattern found in a string.
    subn      Same as sub, but also return the number of substitutions made.
    split     Split a string by the occurrences of a pattern.
    findall   Find all occurrences of a pattern in a string.
    finditer  Return an iterator yielding a Match object for each match.
    compile   Compile a pattern into a Pattern object.
    purge     Clear the regular expression cache.
    escape    Backslash all non-alphanumerics in a string.

Each function other than purge and escape can take an optional 'flags' argument
consisting of one or more of the following module constants, joined by "|".
A, L, and U are mutually exclusive.
    A  ASCII       For string patterns, make \w, \W, \b, \B, \d, \D
                   match the corresponding ASCII character categories
                   (rather than the whole Unicode categories, which is the
                   default).
                   For bytes patterns, this flag is the only available
                   behaviour and needn't be specified.
    I  IGNORECASE  Perform case-insensitive matching.
    L  LOCALE      Make \w, \W, \b, \B, dependent on the current locale.
    M  MULTILINE   "^" matches the beginning of lines (after a newline)
                   as well as the string.
                   "$" matches the end of lines (before a newline) as well
                   as the end of the string.
    S  DOTALL      "." matches any character at all, including the newline.
    X  VERBOSE     Ignore whitespace and comments for nicer looking RE's.
    U  UNICODE     For compatibility only. Ignored for string patterns (it
                   is the default), and forbidden for bytes patterns.

This module also defines an exception 'error'.

)";
std::string test_757 = R"(
	Release the currently checked out license back to the Enterprise Server.

	.. note:: You must authenticate with the Enterprise Server before calling this.

	.. note:: This will deactivate the Binary Ninja Enterprise client. You must call :func:`acquire_license` 	again to continue using Binary Ninja Enterprise in the current process.
	)";
std::string test_758 = R"(
Requests HTTP Library
~~~~~~~~~~~~~~~~~~~~~

Requests is an HTTP library, written in Python, for human beings.
Basic GET usage:

   >>> import requests
   >>> r = requests.get('https://www.python.org')
   >>> r.status_code
   200
   >>> b'Python is a programming language' in r.content
   True

... or POST:

   >>> payload = dict(key1='value1', key2='value2')
   >>> r = requests.post('https://httpbin.org/post', data=payload)
   >>> print(r.text)
   {
     ...
     "form": {
       "key1": "value1",
       "key2": "value2"
     },
     ...
   }

The other HTTP methods are supported - see `requests.api`. Full documentation
is at <https://requests.readthedocs.io>.

:copyright: (c) 2017 by Kenneth Reitz.
:license: Apache 2.0, see LICENSE for more details.
)";
std::string test_759 = R"(
	Get the maximum checkout duration allowed by the Enterprise Server.

	.. note:: You must authenticate with the Enterprise Server before calling this.

	:return: Duration, in seconds, of the maximum time you are allowed to checkout a license.
	)";
std::string test_760 = R"(
	``run_progress_dialog`` runs a given task in a background thread, showing an updating
	progress bar which the user can cancel.

	:param title: Dialog title
	:param can_cancel: If the task can be cancelled
	:param task: Function to perform the task, taking as a parameter a function which should be called to report progress updates and check for cancellation. If the progress function returns false, the user has requested to cancel, and the task should handle this appropriately.
	:return: True if not cancelled
	)";
std::string test_761 = R"(
	Get the build id string of the server

	:return: Build id of the server
	)";
std::string test_762 = R"(
	Get the internal id of the server

	:return: Id of the server
	)";
std::string test_763 = R"(
	Get the display name of the server

	:return: Display name of the server
	)";
std::string test_764 = R"(
	Get the url of the Enterprise Server.

	:return: The current url
	)";
std::string test_765 = R"(
	Get the version number of the server

	:return: Version of the server
	)";
std::string test_766 = R"(
	``set_auto_updates_enabled`` sets auto update enabled status.

	:param bool enabled: True to enable update, False to disable updates.
	:rtype: None
	)";
std::string test_767 = R"(
	Set the url of the Enterprise Server.

	.. note:: This will raise an Exception if the server is already initialized

	:param url: New Enterprise Server url
	)";
std::string test_768 = R"(
	``show_graph_report`` displays a flow graph in UI applications and nothing in command-line applications. 	This API doesn't support clickable references into an existing BinaryView. Use the :py:meth:`BinaryView.show_html_report` 	API if hyperlinking is needed.

	.. note:: This API function will have no effect outside the UI.

	:param FlowGraph graph: Flow graph to display
	:rtype: None
	)";
std::string test_769 = R"(
	``show_html_report`` displays the HTML contents in UI applications and plaintext in command-line 	applications. This API doesn't support hyperlinking into the BinaryView, use the :py:meth:`BinaryView.show_html_report` 	API if hyperlinking is needed.

	:param str contents: HTML contents to display
	:param str plaintext: Plain text version to display (used on the command-line)
	:rtype: None
	:Example:
		>>> show_html_report("title", "<h1>Contents</h1>", "Plain text contents")
		Plain text contents
	)";
std::string test_770 = R"(
	``show_markdown_report`` displays the markdown contents in UI applications and plaintext in command-line 	applications. This API doesn't support hyperlinking into the BinaryView, use the 	:py:meth:`BinaryView.show_markdown_report` API if hyperlinking is needed.

	.. note:: This API function differently on the command-line vs the UI. In the UI a pop-up is used. On the command-line 	a simple text prompt is used.

	:param str contents: markdown contents to display
	:param str plaintext: Plain text version to display (used on the command-line)
	:rtype: None
	:Example:
		>>> show_markdown_report("title", "##Contents", "Plain text contents")
		Plain text contents
	)";
std::string test_771 = R"(
	``show_message_box`` Displays a configurable message box in the UI, or prompts on the console as appropriate

	:param str title: Text title for the message box.
	:param str text: Text for the main body of the message box.
	:param MessageBoxButtonSet buttons: One of :py:class:`MessageBoxButtonSet`
	:param MessageBoxIcon icon: One of :py:class:`MessageBoxIcon`
	:return: Which button was selected
	:rtype: MessageBoxButtonResult
	)";
std::string test_772 = R"(
	``show_plain_text_report`` displays contents to the user in the UI or on the command-line

	.. note:: This API functions differently on the command-line vs the UI. In the UI, a pop-up is used. On the command-line, 	a simple text prompt is used.

	:param str title: title to display in the UI pop-up
	:param str contents: plaintext contents to display
	:rtype: None
	:Example:
		>>> show_plain_text_report("title", "contents")
		contents
	)";
std::string test_773 = R"(
	``show_report_collection`` displays multiple reports in UI applications

	.. note:: This API function will have no effect outside the UI.

	:param ReportCollection reports: Reports to display
	:rtype: None
	)";
std::string test_774 = R"(
	``shutdown`` cleanly shuts down the core, stopping all workers and closing all log files.
	)";
std::string test_775 = R"(
	``simplify_name_to_qualified_name`` simplifies a templated C++ name with default arguments and returns a qualified name.  This can also tokenize a string to a qualified name with/without simplifying it

	:param input_name: String or qualified name to be simplified
	:type input_name: Union[str, QualifiedName]
	:param bool simplify: (optional) Whether to simplify input string (no effect if given a qualified name; will always simplify)
	:return: simplified name (or one-element array containing the input if simplifier fails/cannot simplify)
	:rtype: QualifiedName
	:Example:

		>>> demangle.simplify_name_to_qualified_name(QualifiedName(["std", "__cxx11", "basic_string<wchar, std::char_traits<wchar>, std::allocator<wchar> >"]), True)
		'std::wstring'
		>>>
	)";
std::string test_776 = R"(
	``simplify_name_to_string`` simplifies a templated C++ name with default arguments and returns a string

	:param input_name: String or qualified name to be simplified
	:type input_name: Union[str, QualifiedName]
	:return: simplified name (or original name if simplifier fails/cannot simplify)
	:rtype: str
	:Example:

		>>> demangle.simplify_name_to_string("std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >")
		'std::string'
		>>>
	)";
std::string test_777 = R"(Functions to convert between Python values and C structs.
Python bytes objects are used to hold the data representing the C struct
and also as format strings (explained below) to describe the layout of data
in the C struct.

The optional first format char indicates byte order, size and alignment:
  @: native order, size & alignment (default)
  =: native order, std. size & alignment
  <: little-endian, std. size & alignment
  >: big-endian, std. size & alignment
  !: same as >

The remaining chars indicate types of args and must match exactly;
these can be preceded by a decimal repeat count:
  x: pad byte (no data); c:char; b:signed byte; B:unsigned byte;
  ?: _Bool (requires C99; if not available, char is used instead)
  h:short; H:unsigned short; i:int; I:unsigned int;
  l:long; L:unsigned long; f:float; d:double; e:half-float.
Special cases (preceding decimal count indicates length):
  s:string (array of char); p: pascal string (with count byte).
Special cases (only available in native format):
  n:ssize_t; N:size_t;
  P:an integer type that is wide enough to hold a pointer.
Special case (not in native mode unless 'long long' in platform C):
  q:long long; Q:unsigned long long
Whitespace between formats is ignored.

The variable struct.error is an exception raised on errors.
)";
std::string test_778 = R"(The time value as returned by gmtime(), localtime(), and strptime(), and
 accepted by asctime(), mktime() and strftime().  May be considered as a
 sequence of 9 integers.

 Note that several fields' values are not the same as those defined by
 the C language standard for struct tm.  For example, the value of the
 field tm_year is the actual year, not year - 1900.  See individual
 fields' descriptions for details.)";
std::string test_779 = R"(Subprocesses with accessible I/O streams

This module allows you to spawn processes, connect to their
input/output/error pipes, and obtain their return codes.

For a complete description of this module see the Python documentation.

Main API
========
run(...): Runs a command, waits for it to complete, then returns a
          CompletedProcess instance.
Popen(...): A class for flexibly executing a command in a new process

Constants
---------
DEVNULL: Special value that indicates that os.devnull should be used
PIPE:    Special value that indicates a pipe should be created
STDOUT:  Special value that indicates that stderr should go to stdout


Older API
=========
call(...): Runs a command, waits for it to complete, then returns
    the return code.
check_call(...): Same as call() but raises CalledProcessError()
    if return code is not 0
check_output(...): Same as check_call() but returns the contents of
    stdout instead of a return code
getoutput(...): Runs a command in the shell, waits for it to complete,
    then returns the output
getstatusoutput(...): Runs a command in the shell, waits for it to complete,
    then returns a (exitcode, output) tuple
)";
std::string test_780 = R"(This module provides access to some objects used or maintained by the
interpreter and to functions that interact strongly with the interpreter.

Dynamic objects:

argv -- command line arguments; argv[0] is the script pathname if known
path -- module search path; path[0] is the script directory, else ''
modules -- dictionary of loaded modules

displayhook -- called to show results in an interactive session
excepthook -- called to handle any uncaught exception other than SystemExit
  To customize printing in an interactive session or to install a custom
  top-level exception handler, assign other functions to replace these.

stdin -- standard input file object; used by input()
stdout -- standard output file object; used by print()
stderr -- standard error object; used for error messages
  By assigning other file objects (or objects that behave like files)
  to these, it is possible to redirect all of the interpreter's I/O.

last_type -- type of last uncaught exception
last_value -- value of last uncaught exception
last_traceback -- traceback of last uncaught exception
  These three are only available in an interactive session after a
  traceback has been printed.

Static objects:

builtin_module_names -- tuple of module names built into this interpreter
copyright -- copyright notice pertaining to this interpreter
exec_prefix -- prefix used to find the machine-specific Python library
executable -- absolute path of the executable binary of the Python interpreter
float_info -- a named tuple with information about the float implementation.
float_repr_style -- string indicating the style of repr() output for floats
hash_info -- a named tuple with information about the hash algorithm.
hexversion -- version information encoded as a single integer
implementation -- Python implementation information.
int_info -- a named tuple with information about the int implementation.
maxsize -- the largest supported length of containers.
maxunicode -- the value of the largest Unicode code point
platform -- platform identifier
prefix -- prefix used to find the Python library
thread_info -- a named tuple with information about the thread implementation.
version -- the version of this interpreter as a string
version_info -- version information as a named tuple
__stdin__ -- the original stdin; don't touch!
__stdout__ -- the original stdout; don't touch!
__stderr__ -- the original stderr; don't touch!
__displayhook__ -- the original displayhook; don't touch!
__excepthook__ -- the original excepthook; don't touch!

Functions:

displayhook() -- print an object to the screen, and save it in builtins._
excepthook() -- print an exception and its traceback to sys.stderr
exc_info() -- return thread-safe information about the current exception
exit() -- exit the interpreter by raising SystemExit
getdlopenflags() -- returns flags to be used for dlopen() calls
getprofile() -- get the global profiling function
getrefcount() -- return the reference count for an object (plus one :-)
getrecursionlimit() -- return the max recursion depth for the interpreter
getsizeof() -- return the size of an object in bytes
gettrace() -- get the global debug tracing function
setdlopenflags() -- set the flags to be used for dlopen() calls
setprofile() -- set the global profiling function
setrecursionlimit() -- set the max recursion depth for the interpreter
settrace() -- set the global debug tracing function
)";
std::string test_781 = R"(Thread module emulating a subset of Java's threading model.)";
std::string test_782 = R"(
	Get the token of the currently authenticated user to the Enterprise Server.

	:return: Token, if authenticated. None, otherwise.
	)";
std::string test_783 = R"(Extract, format and print information about Python stack traces.)";
std::string test_784 = R"(
The typing module: Support for gradual typing as defined by PEP 484.

At large scale, the structure of the module is following:
* Imports and exports, all public names should be explicitly added to __all__.
* Internal helper functions: these should never be used in code outside this module.
* _SpecialForm and its instances (special forms):
  Any, NoReturn, ClassVar, Union, Optional, Concatenate
* Classes whose instances can be type arguments in addition to types:
  ForwardRef, TypeVar and ParamSpec
* The core of internal generics API: _GenericAlias and _VariadicGenericAlias, the latter is
  currently only used by Tuple and Callable. All subscripted types like X[int], Union[int, str],
  etc., are instances of either of these classes.
* The public counterpart of the generics API consists of two classes: Generic and Protocol.
* Public helper functions: get_type_hints, overload, cast, no_type_check,
  no_type_check_decorator.
* Generic aliases for collections.abc ABCs and few additional protocols.
* Special types: NewType, NamedTuple, TypedDict.
* Wrapper submodules for re and io related types.
)";
std::string test_785 = R"(
	Acquire or refresh a floating license from the Enterprise server.

	.. note:: You must authenticate with the Enterprise server before calling this.

	:param int duration: Desired length of license checkout, in seconds.
	:param bool _cache: Deprecated but left in for compatibility
	)";
std::string test_786 = R"(Encode a dict or sequence of two-element tuples into a URL query string.

    If any values in the query arg are sequences and doseq is true, each
    sequence element is converted to a separate parameter.

    If the query arg is a sequence of two-element tuples, the order of the
    parameters in the output will match the order of parameters in the
    input.

    The components of a query arg may each be either a string or a bytes type.

    The safe, encoding, and errors parameters are passed down to the function
    specified by quote_via (encoding and errors only if a component is a str).
    )";
std::string test_787 = R"(
		``user_directory`` returns a string containing the path to the `user directory <https://docs.binary.ninja/guide/#user-folder>`_

		:return: current user path
		:rtype: str, or None on failure
	)";
std::string test_788 = R"(
		``user_plugin_path`` returns a string containing the current plugin path inside the `user directory <https://docs.binary.ninja/guide/#user-folder>`_

		:return: current user plugin path
		:rtype: str, or None on failure
	)";
std::string test_789 = R"(
	Get the username of the currently authenticated user to the Enterprise Server.

	:return: Username, if authenticated. None, otherwise.
	)";
std::string test_790 = R"(UUID objects (universally unique identifiers) according to RFC 4122.

This module provides immutable UUID objects (class UUID) and the functions
uuid1(), uuid3(), uuid4(), uuid5() for generating version 1, 3, 4, and 5
UUIDs as specified in RFC 4122.

If all you want is a unique ID, you should probably call uuid1() or uuid4().
Note that uuid1() may compromise privacy since it creates a UUID containing
the computer's network address.  uuid4() creates a random UUID.

Typical usage:

    >>> import uuid

    # make a UUID based on the host ID and current time
    >>> uuid.uuid1()    # doctest: +SKIP
    UUID('a8098c1a-f86e-11da-bd1a-00112444be1e')

    # make a UUID using an MD5 hash of a namespace UUID and a name
    >>> uuid.uuid3(uuid.NAMESPACE_DNS, 'python.org')
    UUID('6fa459ea-ee8a-3ca4-894e-db77e160355e')

    # make a random UUID
    >>> uuid.uuid4()    # doctest: +SKIP
    UUID('16fd2706-8baf-433b-82eb-8c7fada847da')

    # make a UUID using a SHA-1 hash of a namespace UUID and a name
    >>> uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')
    UUID('886313e1-3b8a-5372-9b90-0c9aee199e5d')

    # make a UUID from a string of hex digits (braces and hyphens ignored)
    >>> x = uuid.UUID('{00010203-0405-0607-0809-0a0b0c0d0e0f}')

    # convert a UUID to a string of hex digits in standard form
    >>> str(x)
    '00010203-0405-0607-0809-0a0b0c0d0e0f'

    # get the raw 16 bytes of the UUID
    >>> x.bytes
    b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'

    # make a UUID from a 16-byte string
    >>> uuid.UUID(bytes=x.bytes)
    UUID('00010203-0405-0607-0809-0a0b0c0d0e0f')
)";
std::string test_791 = R"(Python part of the warnings subsystem.)";
std::string test_792 = R"(Interfaces for launching and remotely controlling web browsers.)";
std::vector<std::string> tests = {test_0, test_1, test_2, test_3, test_4, test_5, test_6, test_7, test_8, test_9, test_10, test_11, test_12, test_13, test_14, test_15, test_16, test_17, test_18, test_19, test_20, test_21, test_22, test_23, test_24, test_25, test_26, test_27, test_28, test_29, test_30, test_31, test_32, test_33, test_34, test_35, test_36, test_37, test_38, test_39, test_40, test_41, test_42, test_43, test_44, test_45, test_46, test_47, test_48, test_49, test_50, test_51, test_52, test_53, test_54, test_55, test_56, test_57, test_58, test_59, test_60, test_61, test_62, test_63, test_64, test_65, test_66, test_67, test_68, test_69, test_70, test_71, test_72, test_73, test_74, test_75, test_76, test_77, test_78, test_79, test_80, test_81, test_82, test_83, test_84, test_85, test_86, test_87, test_88, test_89, test_90, test_91, test_92, test_93, test_94, test_95, test_96, test_97, test_98, test_99, test_100, test_101, test_102, test_103, test_104, test_105, test_106, test_107, test_108, test_109, test_110, test_111, test_112, test_113, test_114, test_115, test_116, test_117, test_118, test_119, test_120, test_121, test_122, test_123, test_124, test_125, test_126, test_127, test_128, test_129, test_130, test_131, test_132, test_133, test_134, test_135, test_136, test_137, test_138, test_139, test_140, test_141, test_142, test_143, test_144, test_145, test_146, test_147, test_148, test_149, test_150, test_151, test_152, test_153, test_154, test_155, test_156, test_157, test_158, test_159, test_160, test_161, test_162, test_163, test_164, test_165, test_166, test_167, test_168, test_169, test_170, test_171, test_172, test_173, test_174, test_175, test_176, test_177, test_178, test_179, test_180, test_181, test_182, test_183, test_184, test_185, test_186, test_187, test_188, test_189, test_190, test_191, test_192, test_193, test_194, test_195, test_196, test_197, test_198, test_199, test_200, test_201, test_202, test_203, test_204, test_205, test_206, test_207, test_208, test_209, test_210, test_211, test_212, test_213, test_214, test_215, test_216, test_217, test_218, test_219, test_220, test_221, test_222, test_223, test_224, test_225, test_226, test_227, test_228, test_229, test_230, test_231, test_232, test_233, test_234, test_235, test_236, test_237, test_238, test_239, test_240, test_241, test_242, test_243, test_244, test_245, test_246, test_247, test_248, test_249, test_250, test_251, test_252, test_253, test_254, test_255, test_256, test_257, test_258, test_259, test_260, test_261, test_262, test_263, test_264, test_265, test_266, test_267, test_268, test_269, test_270, test_271, test_272, test_273, test_274, test_275, test_276, test_277, test_278, test_279, test_280, test_281, test_282, test_283, test_284, test_285, test_286, test_287, test_288, test_289, test_290, test_291, test_292, test_293, test_294, test_295, test_296, test_297, test_298, test_299, test_300, test_301, test_302, test_303, test_304, test_305, test_306, test_307, test_308, test_309, test_310, test_311, test_312, test_313, test_314, test_315, test_316, test_317, test_318, test_319, test_320, test_321, test_322, test_323, test_324, test_325, test_326, test_327, test_328, test_329, test_330, test_331, test_332, test_333, test_334, test_335, test_336, test_337, test_338, test_339, test_340, test_341, test_342, test_343, test_344, test_345, test_346, test_347, test_348, test_349, test_350, test_351, test_352, test_353, test_354, test_355, test_356, test_357, test_358, test_359, test_360, test_361, test_362, test_363, test_364, test_365, test_366, test_367, test_368, test_369, test_370, test_371, test_372, test_373, test_374, test_375, test_376, test_377, test_378, test_379, test_380, test_381, test_382, test_383, test_384, test_385, test_386, test_387, test_388, test_389, test_390, test_391, test_392, test_393, test_394, test_395, test_396, test_397, test_398, test_399, test_400, test_401, test_402, test_403, test_404, test_405, test_406, test_407, test_408, test_409, test_410, test_411, test_412, test_413, test_414, test_415, test_416, test_417, test_418, test_419, test_420, test_421, test_422, test_423, test_424, test_425, test_426, test_427, test_428, test_429, test_430, test_431, test_432, test_433, test_434, test_435, test_436, test_437, test_438, test_439, test_440, test_441, test_442, test_443, test_444, test_445, test_446, test_447, test_448, test_449, test_450, test_451, test_452, test_453, test_454, test_455, test_456, test_457, test_458, test_459, test_460, test_461, test_462, test_463, test_464, test_465, test_466, test_467, test_468, test_469, test_470, test_471, test_472, test_473, test_474, test_475, test_476, test_477, test_478, test_479, test_480, test_481, test_482, test_483, test_484, test_485, test_486, test_487, test_488, test_489, test_490, test_491, test_492, test_493, test_494, test_495, test_496, test_497, test_498, test_499, test_500, test_501, test_502, test_503, test_504, test_505, test_506, test_507, test_508, test_509, test_510, test_511, test_512, test_513, test_514, test_515, test_516, test_517, test_518, test_519, test_520, test_521, test_522, test_523, test_524, test_525, test_526, test_527, test_528, test_529, test_530, test_531, test_532, test_533, test_534, test_535, test_536, test_537, test_538, test_539, test_540, test_541, test_542, test_543, test_544, test_545, test_546, test_547, test_548, test_549, test_550, test_551, test_552, test_553, test_554, test_555, test_556, test_557, test_558, test_559, test_560, test_561, test_562, test_563, test_564, test_565, test_566, test_567, test_568, test_569, test_570, test_571, test_572, test_573, test_574, test_575, test_576, test_577, test_578, test_579, test_580, test_581, test_582, test_583, test_584, test_585, test_586, test_587, test_588, test_589, test_590, test_591, test_592, test_593, test_594, test_595, test_596, test_597, test_598, test_599, test_600, test_601, test_602, test_603, test_604, test_605, test_606, test_607, test_608, test_609, test_610, test_611, test_612, test_613, test_614, test_615, test_616, test_617, test_618, test_619, test_620, test_621, test_622, test_623, test_624, test_625, test_626, test_627, test_628, test_629, test_630, test_631, test_632, test_633, test_634, test_635, test_636, test_637, test_638, test_639, test_640, test_641, test_642, test_643, test_644, test_645, test_646, test_647, test_648, test_649, test_650, test_651, test_652, test_653, test_654, test_655, test_656, test_657, test_658, test_659, test_660, test_661, test_662, test_663, test_664, test_665, test_666, test_667, test_668, test_669, test_670, test_671, test_672, test_673, test_674, test_675, test_676, test_677, test_678, test_679, test_680, test_681, test_682,
                                 // broken fmtg test_683,
                                  test_684, test_685, test_686, test_687, test_688, test_689, test_690, test_691, test_692, test_693, test_694, test_695, test_696, test_697, test_698, test_699, test_700, test_701, test_702, test_703, test_704, test_705, test_706, test_707, test_708, test_709, test_710, test_711, test_712, test_713, test_714, test_715, test_716, test_717, test_718, test_719, test_720, test_721, test_722, test_723, test_724, test_725, test_726, test_727, test_728, test_729, test_730, test_731, test_732, test_733, test_734, test_735, test_736, test_737, test_738, test_739, test_740, test_741, test_742, test_743, test_744, test_745, test_746, test_747, test_748, test_749, test_750, test_751, test_752, test_753, test_754, test_755, test_756, test_757, test_758, test_759, test_760, test_761, test_762, test_763, test_764, test_765, test_766, test_767, test_768, test_769, test_770, test_771, test_772, test_773, test_774, test_775, test_776, test_777, test_778, test_779, test_780, test_781, test_782, test_783, test_784, test_785, test_786, test_787, test_788, test_789, test_790, test_791, test_792};

// This one is weirdly formatted all around
// std::vector<std::string> tests = {test_56};

int main(void)
{
    int i = 0;
    for (const auto& test : tests)
    {
        std::cout << std::to_string(i) << "\n\n" << test << std::endl;
        auto docstr = DocString(test);
        std::cout << std::to_string(i) << " --- \n" << DocString::Dump(docstr.allRoot) << std::endl;
        i++;
    }
}
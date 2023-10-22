#

header-only library for converting python docstrings to an AST. 

```cpp 
auto docstr = DocString(test);
// AST is here
// params and ret are also inculded here, can be ignored
docstr.allRoot;

// params and ret AST
docStr.params;
docStr.ret;

// Block visitor. this will go through in sequential order and should be functional for printing a block
docStr.allRoot.VisitBlocks();
```

todo:

better whitespace normalization, fails at this break code-block recognition (this is hard!)

code block description recognition

table parser


current in->out:
``` 
	``run_progress_dialog`` runs a given task in a background thread, showing an updating
	progress bar which the user can cancel.

	:param title: Dialog title
	:param can_cancel: If the task can be cancelled
	:param task: Function to perform the task, taking as a parameter a function which should be called to report progress updates and check for cancellation. If the progress function returns false, the user has requested to cancel, and the task should handle this appropriately.
	:return: True if not cancelled

DocstringRoot
	Param
		ParamName
			Text
			  title
		ParamType
			Text
		ParamDesc
			Text
			   Dialog title
	Param
		ParamName
			Text
			  can_cancel
		ParamType
			Text
		ParamDesc
			Text
			   If the task can be cancelled
	Param
		ParamName
			Text
			  task
		ParamType
			Text
		ParamDesc
			Text
			   Function to perform the task, taking as a parameter a function which should be called to report progress updates and check for cancellation. If the progress function returns false, the user has requested to cancel, and the task should handle this appropriately.
	ReturnBlock
		ReturnDesc
			Text
			  True if not cancelled
	Paragraph
		Text
		Mono
		  run_progress_dialog
		Text
		   runs a given task in a background thread, showing an updating
		  progress bar which the user can cancel.

```
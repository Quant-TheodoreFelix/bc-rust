A crate to produce the cli binary.

Design philosophy of the Command Line Interface is to provide a simple streaming interface to the basic operations where data is read from stdin and written to stdout so that, for example, it can be easily used with linux command-chaining pipes.

Where supported by the underlying internal primitives, data should be processed in a streaming mode with a buffer size around 1 kb so that data can be continuously streamed from stdin to stdout without a large memory footprint or buffering delay.
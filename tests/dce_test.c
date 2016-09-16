#include <compat.h>
#include "dce-test-data.h"
#include "../basic_dce.h"

int main(void)
{
	dma_addr_t input;
	dma_addr_t output;
	size_t input_sz, output_sz, output_produced;
	int ret;

	input_sz = dce_test_data_size;
	input = dce_alloc(input_sz);
	output_sz = input_sz * 2;
	output = dce_alloc(output_sz);

	/* Get input data from sample data file */
	memcpy(input, dce_test_data, input_sz);

	/* Compression */
	ret = bdce_process_data(DCE_COMPRESSION,
			input,
			output,
			input_sz,
			output_sz,
			&output_produced);
	if (ret) {
		printf("DCE returned error code %d\n", ret);
		return -1;
	}
	printf("Compressed %zu bytes into %zu bytes\n",
			input_sz, output_produced);

	/* Decompression */
	memcpy(input, output, output_produced);

	/* The bytes to decomp is equal to the comp output bytes */
	input_sz = output_produced;

	ret = bdce_process_data(DCE_DECOMPRESSION,
			input,
			output,
			input_sz,
			output_sz,
			&output_produced);
	if (ret) {
		printf("DCE returned error code %d\n", ret);
		return -1;
	}
	printf("Decompressed %zu bytes into %zu bytes\n",
			input_sz, output_produced);

	if (memcmp(dce_test_data, output, dce_test_data_size))
		printf("Original input does NOT match decompressed data\n");
	else
		printf("Original input matches decompressed data\n");

	return 0;
}

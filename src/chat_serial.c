/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2015-2016  Dimitrios Kolotouros <dim.kolotouros@gmail.com>,
 *  						 Konstantinos Andrikopoulos <el11151@mail.ntua.gr>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdint.h>
#include <stddef.h>
#include <gcrypt.h>

// TODO allocate memory inside functions
void chat_serial_int16_to_string(int16_t input, unsigned char *output)
{
	output[0] = (input >> 8) & 0xff;
	output[1] = input & 0xff;
}

int16_t chat_serial_string_to_int16(const unsigned char *input)
{
	return input[0] << 8 | input[1];
}

void chat_serial_int_to_string(int input, unsigned char *output)
{
	output[0] = (input >> 24) & 0xff;
	output[1] = (input >> 16) & 0xff;
	output[2] = (input >> 8) & 0xff;
	output[3] = input & 0xff;
}

int chat_serial_string_to_int(const unsigned char *input)
{
	return (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
}

int chat_serial_mpi_to_string(gcry_mpi_t w, unsigned char** output, size_t *size)
{
	gcry_error_t err;
    size_t s;

    err = gcry_mpi_print(GCRYMPI_FMT_HEX, NULL, 0, &s, w);
    if(err)
    	return 1;

    *output = malloc(s * sizeof *output);
    if(!*output)
    	return 1;

    err = gcry_mpi_print(GCRYMPI_FMT_HEX, *output, s, NULL, w);
    if(err) {
    	free(*output);
    	return 1;
    }

    *size = s;

    return 0;
}

//TODO what does size do?
int chat_serial_string_to_mpi(const unsigned char* input, gcry_mpi_t *output, size_t size)
{
	gcry_error_t err;

	//TODO commenting this out to check if scan allocates a new mpi. remove this if it does.
	//*output = gcry_mpi_new(320);

	err = gcry_mpi_scan(output, GCRYMPI_FMT_HEX, input, 0, NULL);
	if(err)
		return 1;

	return 0;
}

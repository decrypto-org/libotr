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

#ifndef SRC_DEBUG_H_
#define SRC_DEBUG_H_

#ifdef DEBUG

/**
 Prints contents of libgcrypt mpi to_print in hexadecimal format

 @param to_print The mpi to be printed
*/
void print_mpi(gcry_mpi_t to_print);


#define DEBUG_MSG(X, ...) fprintf(stderr, "[libotr] %s @ l.%d (%s) " X "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define print_buf(BUF, LEN) do { \
    for(int i = 0; i< (LEN); i++) \
        fprintf(stderr, "%02X", (BUF)[i]); \
    fprintf(stderr,"\n"); \
    } while (0)

#define debug_print_mpi(X) print_mpi((X))

#else

#define DEBUG_MSG(X, ...)
#define debug_print_buffer(X,Y)
#define debug_print_mpi(X)

#endif

#endif /* SRC_DEBUG_H_ */

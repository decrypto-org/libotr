/*
 * debug.c
 *
 *  Created on: Sep 19, 2016
 *      Author: mandragore
 */

#include<stdio.h>

#include<gcrypt.h>

void print_mpi(gcry_mpi_t to_print)
{
    unsigned char *buf;
    size_t s;

    gcry_mpi_print(GCRYMPI_FMT_HEX,NULL,0,&s,to_print);
    buf = malloc(s+2);
    gcry_mpi_print(GCRYMPI_FMT_HEX,buf,s,NULL,to_print);
    buf[s-1]='\n';
    buf[s]='\0';
    fprintf(stderr, buf);
}



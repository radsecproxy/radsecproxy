/*
Copyright (c) 2011, Network RADIUS SARL
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <networkradius-devel/client.h>

/** \file example_3.c
 *  \brief Sample code to initialize a RADIUS packet and a response to it.
 *
 *  This example initializes a packet, and then adds User-Name and
 *  User-Password to it.  The resulting packet is then printed to the
 *  standard output.
 *
 *  As a next step, it then creates the response, and prints that,
 *  too.
 */

static const char *secret = "testing123";
static uint8_t request_buffer[RS_MAX_PACKET_LEN];
static uint8_t response_buffer[RS_MAX_PACKET_LEN];
static RADIUS_PACKET request, response;

int main(int argc, const char *argv[])
{
	int rcode;
	const char *user = "bob";
	const char *password = "password";

	rcode = nr_packet_init(&request, NULL, secret, PW_ACCESS_REQUEST,
			       request_buffer, sizeof(request_buffer));
	if (rcode < 0) {
	error:
		fprintf(stderr, "Error :%s\n",  nr_strerror(rcode));
		return 1;
	}

	if (argc > 1) user = argv[1];
	if (argc > 2) password = argv[2];

	rcode = nr_packet_attr_append(&request, NULL,
				      RS_DA_USER_NAME,
				      user, 0);
	if (rcode < 0) goto error;
	
	rcode = nr_packet_attr_append(&request, NULL,
				      RS_DA_USER_PASSWORD,
				      password, 0);
	if (rcode < 0) goto error;

	/*
	 *	ALWAYS call nr_packet_sign() before sending the packet
	 *	to anyone else!
	 */
	rcode = nr_packet_sign(&request, NULL);
	if (rcode < 0) goto error;

	nr_packet_print_hex(&request);

	rcode = nr_packet_init(&response, &request, secret, PW_ACCESS_ACCEPT,
			       response_buffer, sizeof(response_buffer));
	if (rcode < 0) goto error;

	rcode = nr_packet_attr_append(&response, &request,
				      RS_DA_REPLY_MESSAGE,
				      "Success!", 0);
	if (rcode < 0) goto error;

	rcode = nr_packet_attr_append(&response, &request,
				      RS_DA_TUNNEL_PASSWORD,
				      password, 0);
	if (rcode < 0) goto error;
	rcode = nr_packet_sign(&response, &request);
	if (rcode < 0) goto error;

	nr_packet_print_hex(&response);

	/*
	 *	Check that the response is well-formed.  The
	 *	nr_packet_verify() function also calls nr_packet_ok().
	 *	However, it is sometimes useful to separate "malformed
	 *	packet" errors from "packet is not a response to a
	 *	reqeust" errors.
	 */
	rcode = nr_packet_ok(&response);
	if (rcode < 0) goto error;

	/*
	 *	Double-check the signature of the response.
	 */
	rcode = nr_packet_verify(&response, &request);
	if (rcode < 0) goto error;

	rcode = nr_packet_decode(&response, &request);
	if (rcode < 0) goto error;

	nr_vp_fprintf_list(stdout, response.vps);
	nr_vp_free(&response.vps);

	return 0;
}

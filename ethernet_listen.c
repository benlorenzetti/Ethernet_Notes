/* ethernet_listen.c
 *
 * Builds an 802.3 ethernet frame and then uses Linux sockets to broadcast
 * this packet to all devices on the network. The user passes the data to be
 * sent and the name of the ethernet interface which should be used.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> /* htons () */
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
 
union eth_frame
{
  struct
  {
    unsigned char dest_addr[6]; /* ETH_ALEN = 6 */
    unsigned char src_addr[6];
    unsigned char length[2];
    unsigned char data[1518 - 6 - 6 - 2 - 4];
    unsigned char fcs[4]; /* see note 1 */
  } field;
  unsigned char buffer[1518]; /* 1518 is maximum allowed Eth frame length */
};

/* Note 1:
 * An ethernet "packet" is a 5 MHz preamble + synchronization field of
 * 64 bits, followed by an ethernet "frame". The higher level software
 * (this program or in other cases the OS's TCP/IP stack) is responsible
 * for passing a frame with the fields dest_addr, src_addr, length, and data
 * complete. The ethernet hardware is then responsible for wrapping the
 * supplied frame with preamble+synchronization and a frame check sequence
 * that is computed in hardware.
 * The frame check sequence immediately follows the last byte of data,
 * however long the data may be. In the struct above, it is only located
 * after a full data array for human readability.
 */

char* printsafe_cpy (char*, const union eth_frame*, int);

const unsigned char BROADCAST_ADDRESS[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

unsigned char host_address[ETH_ALEN]; /* ETH_ALEN is 6 */
char interface_name[1000];
int interface_index;
union eth_frame frame1;
int frame_length;
int data_length;
         
int main (int argc, char *argv[])
{
  memset (&frame1, 0, sizeof (frame1));

  /* Get Ethernet Interface Name from User */
  if (argc != 2)
  {
    printf ("Usage: %s <ethernet interface>\n", argv[0]);
    printf ("  where <ethernet interface> is the human readable name of the");
    printf (" sytems' ethernet.\n");
    printf ("  Get the name with command \"$ ifconfig | more\".\n");
    printf ("  Example:\n");
    printf ("  $ %s eth0\n", argv[0]);
    exit (EXIT_FAILURE);
  }

  /* Copy the <ethernet interface> name provided by User */
  strcpy (interface_name, argv[1]);

  /* Open an Ethernet Socket */
  int sfd;
  sfd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (sfd < 0)
  {
    fprintf (stderr, "socket() error %d\n", sfd);
    fprintf (stderr, "(try running with sudo)\n");
    exit (EXIT_FAILURE);
  }

  /* Look Up the Ethernet Interface Index */
  struct ifreq interface_req;
  memset (&interface_req, 0x00, sizeof (interface_req));
  strcpy (interface_req.ifr_name, interface_name);
  if (ioctl (sfd, SIOCGIFINDEX, &interface_req) < 0)
  {
    fprintf (stderr, "ioctl(SIOCGIFINDEX) error.\n");
    exit (EXIT_FAILURE);
  }
  interface_index = interface_req.ifr_ifindex;
/*printf ("Index of interface \"%s\": %d\n", interface_name, interface_index);
*/

  /* Look Up the Source MAC Address */
  if (ioctl (sfd, SIOCGIFHWADDR, &interface_req) < 0)
  {
    fprintf (stderr, "ioctl (SIOCGIFHWADDR) error.\n");
    exit (EXIT_FAILURE);
  }
  memcpy ( (void*)host_address, (void*)(interface_req.ifr_hwaddr.sa_data), ETH_ALEN);
/*printf ("Source MAC Address %d:%d:", (int) mac[0], (int) mac[1]);
  printf ("%d:%d:%d:%d\n", (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
*/

  int count = 0;
  while (1)
  {
    int received = 0;
    received = recvfrom (sfd, (void*)&frame1, ETH_FRAME_LEN, 0, NULL, NULL);
    if (received < 0)
    {
      fprintf (stderr, "recvfrom() error %d\n", received);
      exit (EXIT_FAILURE);
    }
    if (received == 0)
      continue;
    /* If received > 0, then print out the first X chars of data */
    char temp[1500];
    printf ("Packet (%d): %s\n", count++, printsafe_cpy (temp, &frame1, 70));
  }

  /* Close the Socket */
  close (sfd);

  return EXIT_SUCCESS;
}

char* printsafe_cpy (char *dest, const union eth_frame *frame, int max_length)
{
  /* Determine Data Length to Print */
  int length;
  length = 256 * frame->field.length[0] + frame->field.length[1];
  length = (length < 1500) ? length: 1500; /* Max 802.3 data length */
  length = (length < max_length) ? length: max_length;
  /* Convert all special characters to spaces */
  int i;
  const unsigned char *data;
  data = frame->field.data;
  for (i=0; i<length; i++)
  {
    if (0 <= data[i] && data[i] <= 32)
      dest[i] = ' ';
    else if (33 <= data[i] && data[i] <=126)
      dest[i] = data[i];
    else
      dest[i] = ' ';
  }
  /* Null Terminate and Return ptr for fPrinting */
  dest[length] = 0;
  return dest;
}


/*This is an independent source code file containing our interpretation
of the algorithm presented in RFC 815. Due to various constraints, we were
unable to integrate this with our main file but we have, nevertheless,
included the file
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INFINITY 65536
#define PACKETSIZE 500
#define MAXPACKETS 10
#define flagPos 49

char buffer[65536];
struct holeDescriptor
{
	int first;
	int last;
	int nextFirst;
};
typedef struct holeDescriptor hole;

struct fragment
{
	int first;
	int last;
	char packet[PACKETSIZE];
};

void copyHoleDescriptorToHole(hole h1);
int reassembleFragmenttoBuffer(int firstHole);
void enqueue(struct fragment f1);
struct fragment dequeue();
int isEmpty();
struct fragment makeFragment(char *packetrecvd, int offset, int length);
void receivePacket(char* packetrecvd,int offset, int length);
int isLastFragment(struct fragment);

void copyHoleDescriptorToHole(hole h1)
{
	int location = h1.first;
	memcpy((buffer+location),(char*)&h1.first,sizeof(int));
	memcpy((buffer+location+sizeof(int)),(char*)&h1.last,sizeof(int));
	memcpy((buffer+location+2*sizeof(int)),(char*)&h1.nextFirst,sizeof(int));
	return;
}

int reassembleFragmenttoBuffer(int firstHole)
{
	int flag = 1;
	if(firstHole >= INFINITY)
	{
		printf("Packet Reassembled!");
		flag = 0;
		return flag;
	}

	hole temp;
	memcpy((int*)&temp.first,(buffer+firstHole),sizeof(int));
	memcpy((int*)&temp.last,(buffer+firstHole+sizeof(int)),sizeof(int));
	memcpy((int*)&temp.nextFirst,(buffer+firstHole+2*sizeof(int)),sizeof(int));
	/*temp.first = buffer[firstHole];
	temp.last = buffer[firstHole+1];
	temp.nextFirst = buffer[firstHole+2];*/
	if(isEmpty())
		return flag;
	struct fragment frag = dequeue();
	if(frag.first > temp.last)
		return flag;
	if(frag.last < temp.first)
		return flag;
	if(frag.first > temp.first)
	{
		hole newHole;
		newHole.first = temp.first;
		newHole.last = frag.first - 1;
		newHole.nextFirst = frag.last;
		copyHoleDescriptorToHole(newHole);
		return flag;
	}
	if(frag.last < temp.last && isLastFragment(frag))
	{
		hole newHole;
		newHole.first = frag.last + 1;
		newHole.last = temp.last;
		newHole.nextFirst = -1;
		copyHoleDescriptorToHole(newHole);
		return flag;
	}

	return flag;

}

static struct fragment queue[MAXPACKETS];
int front = -1;
int rear = -1;

void enqueue(struct fragment f1)
{
	if(rear >= MAXPACKETS - 1)
		return;
	if(front == -1)
		front = 0;
	rear = rear + 1;
	queue[rear] = f1;
	return;
}

struct fragment dequeue()
{
	if(!(front == -1 || front > rear))
	{
		struct fragment f1 = queue[front];
		front = front + 1;
		return f1;
	}
	return makeFragment("",-1,-1);
}

int isEmpty()
{
	if(front == -1)
		return 1;
	return 0;
}
struct fragment makeFragment(char *packetrecvd, int offset, int length)
{
	struct fragment f1;
	f1.first = offset*8;
	f1.last =  f1.first + length - 20;
	strcpy(f1.packet,packetrecvd);
	return f1;
}

void receivePacket(char* packetrecvd,int offset, int length)
{
	struct fragment f1 = makeFragment(packetrecvd, offset, length);
	enqueue(f1);
}

int isLastFragment(struct fragment f1)
{
	if(f1.packet[flagPos] == 0)
		return 1;
	else return 0;
}
int main()
{
	hole firstHoleDescriptor;
	firstHoleDescriptor.first = 0;
	firstHoleDescriptor.last = INFINITY;
	firstHoleDescriptor.nextFirst = -1;

	int flag, count = 0;
	do
	{
		flag = reassembleFragmenttoBuffer(firstHoleDescriptor.first);
		count++;
		if(count == 1000)
			break;

	}
	while(flag&&(!isEmpty()));

	return 0;
}
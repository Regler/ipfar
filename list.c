#include "list.h"
#include <stdlib.h>
//创建链表
MyList * createMyList()
{
	MyList *list = (MyList *) malloc(sizeof(MyList));
	if (!list)  
	{
		//		printf("申请内存失败\n");
		return NULL;
	}
	list->length = 0;
	list->first = NULL;
	list->last = NULL;
	return list;
}

//释放链表
void freeMyList(MyList* list,void(*freeData)(void *))
{
	MyNode *p = NULL;
	while (list->first)
	{
		p = list->first->next;
		(*freeData)(list->first->data);
		free(list->first);
		list->first = p;
	}	
	free(list);
}

//链表的反向
void myListReverse(MyList *list)
{
	if (list == NULL && list->first == NULL)  return ;
	MyNode *p = list->last;
	MyNode *temp = p->next;
	list->last = list->first;
	list->first = p;
	while (p)
	{
		temp = p->next;
		p->next = p->prior;
		p->prior = temp;
		p = p->next;	
	}
}


//插入在尾部
void myListInsertDataAtLast(MyList* const list, void* const data)
{
	MyNode *node = (MyNode *) malloc(sizeof(MyNode));
	if (!node) 
	{
		//		printf("申请内存失败\n");
		return;
	}
	node->data = data;
	node->next = NULL;
	if (list->length)
	{
		list->last->next = node;
		node->prior=list->last;
		list->last = node;
	} 
	else
	{
		node->prior = NULL;
		list->first = node;
		list->last = node;
	}
	(list->length)++;
}

//插入在首部
void myListInsertDataAtFirst(MyList* const list, void* const data)
{
	MyNode *node = (MyNode *) malloc(sizeof(MyNode));
	if (!node) 
	{
		//	printf("申请内存失败\n");
		return;
	}
	node->data = data;
	node->prior = NULL;
	if (list->length)
	{
		node->next = list->first;
		list->first->prior = node;
		list->first = node;
	}
	else
	{
		node->next = NULL;
		list->first = node;
		list->last = node;
	}
	(list->length)++;
}

//长度
int myListGetSize(const MyList* const list)
{
	return list->length;
}

//打印
void myListOutput(const MyList* const list, void(*pt)(const void* const))
{
	MyNode *p = list->first;
	while (p)
	{
		(*pt)(p->data);
		p = p->next;
	}
}


//反向打印
void myListOutput_reverse(const MyList* const list,void(*pt)(const void* const) )
{
	MyNode *p = list->last;
	while(p)
	{
		(*pt)(p->data);
		p = p->prior;
	}
	puts("");
}

//删除在尾部
void* myListRemoveDataAtLast(MyList* const list)
{
	if (list->length == 0)  
	{
		//   printf("链表为NULL\n");
		return NULL;
	}
	if (list->length == 1)
	{
		return myListRemoveDataAtFirst(list);
	}
	MyNode *p = list->last;
	void *value = p->data;
	list->last = p->prior;
	list->last->next = NULL;
	free(p);
	(list->length)--;
	return value;
}

//删除在首部
void* myListRemoveDataAtFirst(MyList* const list)
{
	if (list->length == 0)  
	{
		//   printf("链表为NULL\n");
		return NULL;
	}
	MyNode *p = list->first;
	list->first = p->next;
	list->first->prior = NULL;
	void * value = p->data;
	free(p);
	(list->length)--;
	if (list->length == 0)
	{
		list->last = NULL;
	}
	return value;
}



//插入
int myListInsertDataAt(MyList* const list, void* const data, int index)
{
	if (index  < 0 || index > list->length) 
	{
		//   printf("插入范围错误\n");
		return 0;
	}
	if (index == 0)
	{
		myListInsertDataAtFirst(list, data);
		return 1;
	}
	if (index == list->length)
	{
		myListInsertDataAtLast(list, data);
		return 1;
	}
	MyNode *node = (MyNode *) malloc(sizeof(MyNode));
	if (node == NULL)  
	{
		printf("申请内存失败\n");
		return 0;
	}
	node->data = data;
	MyNode *p = NULL;
	int mid = list->length/2;
	if (index < mid)
	{
		p = list->first;
		for (int i = 1; i < index; i++)
		{
			p = p->next;
		}
	}
	else 
	{
		p = list->last;
		for (int i = list->length; i > index; i--)
		{
			p=p->prior;
		}
	}
	node->next = p->next;
	p->next->prior = node;
	p->next = node;
	node->prior = p;
	(list->length)++;
	return 1;
}

//删除
void* myListRemoveDataAt(MyList* const list, int index)
{
	if (index  < 0 || index >= list->length) 
	{
		//   printf("删除范围错误\n");
		return NULL;
	}
	if (index == 0)
	{
		return myListRemoveDataAtFirst(list);
	}
	if (index == list->length - 1)
	{
		return myListRemoveDataAtLast(list);
	}
	int mid = list->length/2;
	MyNode *p = NULL;
	MyNode *temp = NULL;
	if (index < mid)
	{
		p = list->first;
		for (int i=1; i < index; i++)
		{ 
			p=p->next;
		}

	}
	else 
	{
		p = list->last;
		for( int i = list->length; i > index; i--)
		{   
			p=p->prior;
		}
	}
	temp = p->next;
	void *value = temp->data;
	p->next = temp->next;
	temp->next->prior = p;
	free(temp);
	(list->length)--;
	return value;
}

//取得数据
void* myListGetDataAt(const MyList* const list, int index)
{
	if (index  < 0 || index > list->length - 1 ) 
	{
		printf("查找范围错误\n");
		return NULL;
	}
	int mid = list->length/2;
	MyNode *p = NULL ;
	if (index < mid )
	{
		p = list->first;
		for(int i=1; i <= index; i++)
		{ 
			p = p->next;	
		}
	}
	else 
	{
		p = list->last;
		for(int i = list->length; i > index + 1; i--)
		{
			p = p->prior;
		}
	}
	return p->data;   


}

//取得第一个数据
void* myListGetDataAtFirst(const MyList* const list)
{
	return list->first->data;
}

//取得最后一个数据
void* myListGetDataAtLast(const MyList* const list)
{
	return list->last->data;
}

//按照某种条件查找第一个节点
MyNode*  myListFindDataNode(const MyList* const list ,const void* const data,int(*pt)(const void* const,const void* const))
{
	MyNode *p = list ->first;
	while(p)
	{
		if ((*pt)(p->data,data)) 
		{
			return p;
		}
		p = p->next;
	}
	return NULL;
}

//按照某种条件查找第一个节点
int  myListFindDataNodeindex( MyList *list ,int(*pt)( void*))
{
	MyNode *p = list ->first;
	int index = 0;
	while(p)
	{
		if ((*pt)(p->data)==1) 
		{
			return index;
		}
		index++;
		p = p->next;
	}
	return -1;
}






//按照某种条件查找所有节点
MyList*  myListFindDataAllNode( MyList*  list ,int(*pt)( void*), void (*freedata)(void *))
{
	MyNode *p = list ->first;
	MyList *newList = NULL;
	newList = createMyList();
	while(p)
	{
		if ((*pt)(p->data)) 
		{
			//	temp = (MyNode *) malloc(sizeof(MyNode));
			//	if (temp != NULL)
			//	temp->data = p->data;
			//	else return NULL;
			myListInsertDataAtLast(newList, p->data);
		}
		else 
		{
			(*freedata)(p->data);
		}
		p = p->next;
	}
	p = NULL;
	while (list->first)
	{
		p = list->first->next;
		free(list->first);
		list->first = p;
	}	
	free(list);

	return newList;
}










//快速排序  内部不给用户
void myListQuicksort(MyNode* first, MyNode* last,int(*pt)( void*  , void* ))
{
	if (first == last || !first || !last)  
	{
		return ;
	}
	MyNode *low = first;
	MyNode *high = last;
	void *  p=first->data;
	while(first != last)
	{
		while (first != last && (*pt)(p,last->data)) 
		{
			last = last->prior;
		}
		if (first != last)
		{
			first->data = last->data;
			first = first->next; 
		}
		else break;
		while (first != last && (*pt)(first->data,p))
		{
			first = first->next;
		}
		if (first != last)
		{
			last->data = first->data;
			last = last->prior;
		}
		else break;
	}
	last->data = p;

	if (low != first)
	{
		myListQuicksort(low,first->prior,(*pt));
	}
	if (first!=high)  
	{
		myListQuicksort(first->next,high,(*pt));
	}
}


void  myListQuickSort(MyList * const list ,int(*cmp)( void *  , void * ))
{
	MyNode *first = list->first;
	MyNode *last = list->last;
	myListQuicksort(first, last, (*cmp));
}


//插入排序
void myListInsertSort(MyList *const list, int (*cmp)( void * ,  void * ))
{
	if(list == NULL)	return ;
	MyNode *p = list->first;
	MyNode *now = p->next;
	MyNode *nownext = NULL;
	while (now)
	{	nownext = now->next;
		for(p = list->first;(*cmp)(p->data, now->data) && p && p != now; p = p->next );
		if (p != list->first && p !=now )  
		{
			if(nownext == NULL) 
			{
				now->prior->next = NULL;
				list->last = now->prior;
			}
			else	
			{
				now->prior->next = now->next;
				now->next->prior = now->prior;
			}
			now->next = p;
			now->prior = p->prior;
			p->prior->next = now;
			p->prior = now;
		}
		else if(p == list->first)
		{		
			if(nownext == NULL) 
			{
				now->prior->next = NULL;
				list->last = now->prior;
			}
			else	
			{
				now->prior->next = now->next;
				now->next->prior = now->prior;
			}
			p->prior = now;
			now->next = p;
			now->prior = NULL;
			list->first = now ;
		}

		now = nownext;
	}
}

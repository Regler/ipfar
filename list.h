#ifndef LIST_H_INCLUDED
#define LIST_H_INCLUDED
#include <stdio.h>


typedef struct myNode
{
	void * data;
    struct myNode *prior;
	struct myNode *next;
} MyNode;

typedef struct myList
{
	MyNode * first;
	MyNode * last;
	int length;
} MyList;


//创建链表
MyList * createMyList();

//链表的反向
void myListReverse(MyList *list);

//释放链表
void freeMyList(MyList * list, void(*freeData)(void *));

//插入在尾部
void myListInsertDataAtLast(MyList* const list, void* const data);

//插入在首部
void myListInsertDataAtFirst(MyList * const list, void* const data);

//插入
int myListInsertDataAt(MyList * const list, void* const data, int index);

//删除在尾部
void* myListRemoveDataAtLast(MyList* const list);

//删除在首部
void* myListRemoveDataAtFirst(MyList * const list);

//删除
void* myListRemoveDataAt(MyList* const list, int index);

//删除对象,返回是否删除成功
int myListRemoveDataObject(MyList* const list, void * data);

//长度
int myListGetSize(const MyList * const list);

//打印
void myListOutput(const MyList * const list, void(*pt)(const void * const));

//查询节点
MyNode* myListFindDataNode(const MyList * const list,const void * const ,int(*pt)(const void * const,const void * const));

//查询满足调件节点下标
int  myListFindDataNodeindex( MyList*  list ,int(*pt)( void*));

//查询所有节点
MyList* myListFindDataAllNode( MyList *  list ,int(*pt)( void * ), void (*freedata)(void *));

//反向打印
void myListOutput_reverse(const MyList * const list, void (*f)(const void * const));

//取得数据
void* myListGetDataAt(const MyList * const list, int index);

//取得第一个数据
void* myListGetDataAtFirst(const MyList * const list);

//取得最后一个数据
void* myListGetDataAtLast(const MyList * const list);

//快速排序
void  myListQuickSort(MyList * const list,int(*pt)( void *  , void * ));

void myListInsertSort(MyList *const list, int (*cmp)( void * ,  void * ));

#endif // LIST_H_INCLUDED

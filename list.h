struct list_node {
    struct list_node *next;
    void *data;
};

struct list {
    struct list_node *first, *last;
};

/* allocates and initialises list structure; returns NULL if malloc fails */
struct list *list_create();

/* frees all memory associated with the list */
void list_destroy(struct list *list);

/* appends entry to list; returns 1 if ok, 0 if malloc fails */
int list_add(struct list *list, void *data);

/* returns first node */
struct list_node *list_first(struct list *list);

/* returns the next node after the argument */
struct list_node *list_next(struct list_node *node);

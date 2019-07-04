struct safe_string {
	uint8_t const* buffer;
	size_t length;
};

struct dom_node {
	struct safe_string* name;
	struct safe_string* content;
	struct dom_node** children; // I wish i had children
};

struct dom_document { 
	struct {
		uint8_t* buffer;
		size_t length;
	} buffer;

	struct dom_node* root;
};

struct dom_parser {
	uint8_t* buffer;
	size_t position;
	size_t length;
};

enum dom_parser_offset {
	NO_CHARACTER = -1,
	CURRENT_CHARACTER = 0,
	NEXT_CHARACTER = 1,
};

static size_t get_array_elements(struct dom_node** nodes) {
	size_t elements = 0;

	while (nodes[elements]) {
		++elements;
	}

	return elements;
}

static bool safe_string_equals(struct safe_string* a, struct safe_string* b) {
    for (size_t i = 0; i < a->length; ++i) {
		if (a->buffer[i] != b->buffer[i]) {
			return false;
		}
	}

	if (a->length != b->length) {
		return false;
	}


	return true;
}

static uint8_t* safe_string_clone(struct safe_string* s) {
	if (!s) {
		return 0;
	}

	uint8_t* clone = calloc(s->length + 1, sizeof(uint8_t));

	safe_string_copy(s, clone, s->length);
	clone[s->length] = 0;

	return clone;
}

static void safe_string_free(struct safe_string* string) {
	free(string);
}

static void dom_node_free(struct dom_node* node) {
	safe_string_free(node->name);

	if (node->content) {
		safe_string_free(node->content);
	}

    safe_string_free(node->content);
	struct dom_node** it = node->children;
	while (*it) {
		dom_node_free(*it);
		++it;
	}
	free(node->children);

	free(node);
}

static uint8_t dom_parser_peek(struct dom_parser* parser, size_t n) {
	size_t position = parser->position;

	while (position < parser->length) {
		if (!isspace(parser->buffer[position])) {
			if (n == 0) {
				return parser->buffer[position];
			} else {
				--n;
			}
		}

		position++;
	}

	return 0;
}

static void dom_parser_consume(struct dom_parser* parser, size_t n) {
	/* Move the position forward
	 */
	parser->position += n;

	/* Don't go too far
	 *
	 * Valid because parser->length must be greater than 0
	 */
	if (parser->position >= parser->length) {
		parser->position = parser->length - 1;
	}
}

static void dom_skip_whitespace(struct dom_parser* parser) {
	while (isspace(parser->buffer[parser->position])) {
		if (parser->position + 1 >= parser->length) {
			return;
		} else {
			parser->position++;
		}
	}
}

static struct safe_string* dom_parse_tag_end(struct dom_parser* parser) {
	size_t start = parser->position;
	size_t length = 0;

	/* Parse until `>' or a whitespace is reached
	 */
	while (start + length < parser->length) {
		uint8_t current = dom_parser_peek(parser, CURRENT_CHARACTER);

		if (('>' == current) || isspace(current)) {
			break;
		} else {
			dom_parser_consume(parser, 1);
			length++;
		}
	}

	/* Consume `>'
	 */
	if ('>' != dom_parser_peek(parser, CURRENT_CHARACTER)) {
		return 0;
	}
	dom_parser_consume(parser, 1);

	/* Return parsed tag name
	 */
	struct safe_string* name = malloc(sizeof(struct safe_string));
	name->buffer = &parser->buffer[start];
	name->length = length;
	return name;
}

static struct safe_string* dom_parse_tag_open(struct dom_parser* parser) {
	dom_skip_whitespace(parser);

	/* Consume `<'
	 */
	if ('<' != dom_parser_peek(parser, CURRENT_CHARACTER)) {
		return 0;
	}
	dom_parser_consume(parser, 1);

	/* Consume tag name
	 */
	return dom_parse_tag_end(parser);
}


static struct safe_string* dom_parse_tag_close(struct dom_parser* parser) {
	dom_skip_whitespace(parser);

	/* Consume `</'
	 */
	if (('<' != dom_parser_peek(parser, CURRENT_CHARACTER))
		||	('/' != dom_parser_peek(parser, NEXT_CHARACTER))) {

		if ('<' != dom_parser_peek(parser, CURRENT_CHARACTER)) {
            return 0;
		}
		if ('/' != dom_parser_peek(parser, NEXT_CHARACTER)) {
		    return 0;
        }

		return 0;
	}
	dom_parser_consume(parser, 2);

	/* Consume tag name
	 */
	return dom_parse_tag_end(parser);
}



static struct safe_string* dom_parse_content(struct dom_parser* parser) {
	/* Whitespace will be ignored
	 */
	dom_skip_whitespace(parser);

	size_t start = parser->position;
	size_t length = 0;

	/* Consume until `<' is reached
	 */
	while (start + length < parser->length) {
		uint8_t current = dom_parser_peek(parser, CURRENT_CHARACTER);

		if ('<' == current) {
			break;
		} else {
			dom_parser_consume(parser, 1);
			length++;
		}
	}

	/* Next character must be an `<' or we have reached end of file
	 */
	if ('<' != dom_parser_peek(parser, CURRENT_CHARACTER)) {
		return 0;
	}

	/* Ignore tailing whitespace
	 */
	while ((length > 0) && isspace(parser->buffer[start + length - 1])) {
		length--;
	}

	/* Return text
	 */
	struct safe_string* content = malloc(sizeof(struct safe_string));
	content->buffer = &parser->buffer[start];
	content->length = length;
	return content;
}


static struct dom_node* dom_parse_node(struct dom_parser* parser) {
	/* Setup variables
	 */
	struct safe_string* tag_open = 0;
	struct safe_string* tag_close = 0;
	struct safe_string* content = 0;

	struct dom_node** children = calloc(1, sizeof(struct dom_node*));
	children[0] = 0;


	/* Parse open tag
	 */
	tag_open = dom_parse_tag_open(parser);
	if (!tag_open) {
		goto exit_failure;
	}

	/* If tag ends with `/' it's self closing, skip content lookup */
	if (tag_open->length > 0 && '/' == tag_open->buffer[tag_open->length - 1]) {
		/* Drop `/'
		 */
		--tag_open->length;
		goto node_creation;
	}

	/* If the content does not start with '<', a text content is assumed
	 */
	if ('<' != dom_parser_peek(parser, CURRENT_CHARACTER)) {
		content = dom_parse_content(parser);

		if (!content) {
			goto exit_failure;
		}


	/* Otherwise children are to be expected
	 */
	} else while ('/' != dom_parser_peek(parser, NEXT_CHARACTER)) {

		/* Parse child node
		 */
		struct dom_node* child = dom_parse_node(parser);
		if (!child) {
			goto exit_failure;
		}

		/* Grow child array :)
		 */
		size_t old_elements = get_zero_terminated_array_elements(children);
		size_t new_elements = old_elements + 1;
		children = realloc(children, (new_elements + 1) * sizeof(struct dom_node*));

		/* Save child
		 */
		children[new_elements - 1] = child;
		children[new_elements] = 0;
	}


	/* Parse close tag
	 */
	tag_close = dom_parse_tag_close(parser);
	if (!tag_close) {
		goto exit_failure;
	}


	/* Close tag has to match open tag
	 */
	if (!safe_string_equals(tag_open, tag_close)) {
		goto exit_failure;
	}


	/* Return parsed node
	 */
	safe_string_free(tag_close);

node_creation:;
	struct dom_node* node = malloc(sizeof(struct dom_node));
	node->name = tag_open;
	node->content = content;
	node->children = children;
	return node;


	/* A failure occured, so free all allocated resources
	 */
exit_failure:
	if (tag_open) {
		safe_string_free(tag_open);
	}
	if (tag_close) {
		safe_string_free(tag_close);
	}
	if (content) {
		safe_string_free(content);
	}

	struct dom_node** it = children;
	while (*it) {
		dom_node_free(*it);
		++it;
	}
	free(children);

	return 0;
}

/** ================================================== */
/** ================================================== */
/** ================================================== */
/** ================================================== */
/** ================================================== */
/** All functions after HERE can be called by the user */
/** ================================================== */
/** ================================================== */
/** ================================================== */
/** ================================================== */
/** ================================================== */
struct dom_document* dom_parse_document(uint8_t* buffer, size_t length) {
	/* Initialize parser
	 */
	struct dom_parser parser = {
		.buffer = buffer,
		.position = 0,
		.length = length
	};

	/* An empty buffer can never contain a valid document
	 */
	if (!length) {
		return 0;
	}

	/* Parse the root node
	 */
	struct dom_node* root = dom_parse_node(&parser);
	if (!root) {
		return 0;
	}

	/* Return parsed document
	 */
	struct dom_document* document = malloc(sizeof(struct dom_document));
    memset(document, sizeof(struct dom_document) , 0);
	document->buffer.buffer = buffer;
	document->buffer.length = length;
	document->root = root;

	return document;
}

void dom_document_free(struct dom_document* document, bool free_buffer) {
	dom_node_free(document->root);

	if (free_buffer) {
		free(document->buffer.buffer);
	}
	free(document);
}

struct dom_node* dom_document_root(struct dom_document* document) {
	return document->root;
}


struct safe_string* dom_node_name(struct dom_node* node) {
	return node->name;
}


struct safe_string* dom_node_content(struct dom_node* node) {
	return node->content;
}

size_t dom_node_children(struct dom_node* node) {
	return get_zero_terminated_array_elements(node->children);
}

struct dom_node* dom_node_child(struct dom_node* node, size_t child) {
	if (child >= dom_node_children(node)) {
		return 0;
	}

	return node->children[child];
}

void safe_string_copy(struct safe_string* string, uint8_t* buffer, size_t length) {
	if (!string) {
		return;
	}
    #define MAX_STRLEN 8192
    // Gotta include header size
    if (length + 8 > string->length) {
        return;
    }
    
    // Check for overflow
    if (length + 8 < 0 || length + 8 > MAX_STRLEN) {
        length = MAX_STRLEN;
    }
    
	memcpy(buffer, string->buffer, length);
}



struct dom_node* dom_easy_child(struct dom_node* node, uint32_t child_name_length, uint8_t const* child_name, ...) {

	/* Find children, one by one
	 */
	struct dom_node* current = node;

	va_list arguments;
	va_start(arguments, child_name);


	/* Descent to current.child
	 */
	while (child_name) {

		/* Convert child_name to safe_string for easy comparison
		 */
		struct safe_string cn = {
			.buffer = malloc(strlen(child_name)),
			.length = strlen(child_name)
		};
    
        safe_string_copy(cn, child_name, child_name);

		/* Interate through all children
		 */
		struct dom_node* next = 0;

		size_t i = 0; for (; i < dom_node_children(current); ++i) {
			struct dom_node* child = dom_node_child(current, i);

			if (safe_string_equals(dom_node_name(child), &cn)) {
				if (!next) {
					next = child;

				/* Two children with the same name
				 */
				} else {
					va_end(arguments);
					return 0;
				}
			}
		}

		/* No child with that name found
		 */
		if (!next) {
			va_end(arguments);
			return 0;
		}
		current = next;		
		
		/* Find name of next child
		 */
		child_name = va_arg(arguments, uint8_t const*);
	}
	va_end(arguments);


	/* Return current element
	 */
	return current;
}

uint8_t* dom_easy_name(struct dom_node* node) {
	if (!node) {
		return 0;
	}

	return safe_string_clone(dom_node_name(node));
}


uint8_t* dom_easy_content(struct dom_node* node) {
	if (!node) {
		return 0;
	}

	return safe_string_clone(dom_node_content(node));
}

size_t safe_string_length(struct safe_string* string) {
	if (!string) {
		return 0;
	}
	return string->length;
}



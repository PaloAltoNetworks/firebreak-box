RST2HTML = rst2html
OPTIONS =
SOURCE = firebreak-box.html boxoauth2.html

.SUFFIXES: .rst .html
.rst.html:
	$(RST2HTML) $(OPTIONS) $< $@

all: $(SOURCE)

clean:
	rm -f $(SOURCE)

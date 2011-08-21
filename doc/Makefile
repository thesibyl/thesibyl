POD2HT=pod2html 
HTOPT=--title "The Sibyl" --noindex

SED=sed
SEDOPT= -e '/__index__/d ; /<hr \/>/d'

TEX=pdflatex


WWW_PATH = ~/Sites/sibyl

default:
	$(POD2HT) $(HTOPT) download.pod | \
		$(SED) $(SEDOPT) > $(WWW_PATH)/download.html

	cd sibyl_step_by_step ; \
	$(POD2HT) $(HTOPT) sibyl_step_by_step.pod | \
		$(SED) $(SEDOPT) \
			> $(WWW_PATH)/sibyl_step_by_step.html

	$(POD2HT) $(HTOPT) faq.pod | \
		$(SED) $(SEDOPT) > $(WWW_PATH)/faq.html

	$(POD2HT) $(HTOPT) technical.pod | \
		$(SED) $(SEDOPT) > $(WWW_PATH)/technical.html

	$(POD2HT) $(HTOPT) INSTALL.pod | \
		$(SED) $(SEDOPT) > $(WWW_PATH)/install.html

	$(TEX) sibyl-doc.ltx && cp sibyl-doc.pdf ~/Sites/sibyl/sibyl-doc.pdf

clean:
	rm -f *{aux,log,pdf,~,tmp}

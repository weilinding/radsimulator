CFLAGS = -I/usr/local/opt/openssl@1.0.2t/include -Wall -g -pthread
LFLAGS = -gstabs -pthread -lcrypto
EXEC_FILES = radcl_sim

all: $(EXEC_FILES)

radcl_sim: \
	radcl_main.o \
	rad_crypto.o \
	rad_script.o \
	rad_eap_sim_tuples.o \
	rad_avp_encode.o \
	rad_eap_encode.o \
	rad_avp_decode.o \
	rad_eap_decode.o
	gcc -o $@ $^  $(LFLAGS)

rad_gen_user_conf: rad_gen_user_conf.o
	gcc $(LFLAGS) -o $@ $^

rad_gen_user_conf.o : rad_gen_user_conf.c
	gcc $(CFLAGS) -c -o $@ $<

radcl_main.o: radcl_main.c
	gcc $(CFLAGS) -c -o $@ $<

rad_script.o: rad_script.c
	gcc $(CFLAGS) -c -o $@ $<

rad_crypto.o: rad_crypto.c
	gcc $(CFLAGS) -c -o $@ $<

rad_avp_encode.o: rad_avp_encode.c
	gcc $(CFLAGS) -c -o $@ $<

rad_eap_encode.o: rad_eap_encode.c
	gcc $(CFLAGS) -c -o $@ $<

rad_avp_decode.o: rad_avp_decode.c
	gcc $(CFLAGS) -c -o $@ $<

rad_eap_decode.o: rad_eap_decode.c
	gcc $(CFLAGS) -c -o $@ $<

rad_eap_sim_tuples.o: rad_eap_sim_tuples.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(EXEC_FILES) *.o *~

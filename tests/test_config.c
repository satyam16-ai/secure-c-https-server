#include <check.h>
#include "../include/config.h"

START_TEST(test_config_load_defaults)
{
    server_config_t config = {0};
    ck_assert_int_eq(config_load("server.conf", &config), 0);
    ck_assert_int_eq(config.port, 8080);
    ck_assert_str_eq(config.cert_file, "certs/cert.pem");
    ck_assert_str_eq(config.key_file, "certs/key.pem");
    ck_assert_str_eq(config.static_dir, "static");
    ck_assert_str_eq(config.log_dir, "logs");
    ck_assert_int_eq(config.max_clients, 1024);
    ck_assert_int_eq(config.backlog, 128);
    ck_assert_int_eq(config.debug, 1);
    config_free(&config);
}
END_TEST

Suite *config_suite(void)
{
    Suite *s = suite_create("Config");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_config_load_defaults);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = config_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? 0 : 1;
}
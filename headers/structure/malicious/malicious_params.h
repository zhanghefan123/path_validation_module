//
// Created by zhf on 2026/3/30.
//

#ifndef PATH_VALIDATION_MODULE_MALICIOUS_PARAMS_H
#define PATH_VALIDATION_MODULE_MALICIOUS_PARAMS_H
struct MaliciousParams {
    int corrupt_ratio_start;
    int corrupt_ratio_end;
    int corrupt_special_ratio_start;
    int corrupt_special_ratio_end;
};

struct MaliciousParams* init_malicious_params(void);

void free_malicious_params(struct MaliciousParams* malicious_params);

#endif //PATH_VALIDATION_MODULE_MALICIOUS_PARAMS_H

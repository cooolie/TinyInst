/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string>

#include "common.h"
#include "litecov.h"

uint8_t* trace_bits;

LiteCov* instrumentation;
bool persist;
int num_iterations;
int cur_iteration;

// run a single iteration over the target process
// whether it's the whole process or target method
// and regardless if the target is persistent or not
// (should know what to do in pretty much all cases)
std::string RunTarget(int argc, char** argv, unsigned int pid, uint32_t timeout) {
	DebuggerStatus status;

	//if (!instrumentation->IsTargetFunctionDefined()) {
	//    return "ERR:!IsTargetFunctionDefined\n";
	//}

	// else clear only when the target function is reached
	//if (!instrumentation->IsTargetFunctionDefined()) {
	//  instrumentation->ClearCoverage();
	//}

	if (instrumentation->IsTargetAlive() && persist) {
		status = instrumentation->Continue(timeout);
	}
	else {
		instrumentation->Kill();
		cur_iteration = 0;
		if (argc) {
			status = instrumentation->Run(argc, argv, timeout);
		}
		else {
			status = instrumentation->Attach(pid, timeout);
		}
	}

	// if target function is defined,
	// we should wait until it is hit
	if (instrumentation->IsTargetFunctionDefined()) {
		if ((status != DEBUGGER_TARGET_START) && argc) {
			// try again with a clean process
			  //选择的点无论文件是否正常都会触发，不触发就有问题
			return "ERR:Target function not reached, retrying with a clean process\n";
		}

		if (status != DEBUGGER_TARGET_START) {
			switch (status) {
			case DEBUGGER_CRASHED:
				return "ERR: Process crashed before reaching the target method\n";
				break;
			case DEBUGGER_HANGED:
				return ("ERR: Process hanged before reaching the target method\n");
				break;
			case DEBUGGER_PROCESS_EXIT:
				return("ERR: Process exited before reaching the target method\n");
				break;
			default:
				return ("ERR: An unknown problem occured before reaching the target method\n");
				break;
			}
		}


		// 也就是在 TAGET methon 外执行到了 需要 instrment 模块的代码
		Coverage newcoverage;
		instrumentation->GetCoverage(newcoverage, true);
		for (auto iter = newcoverage.begin(); iter != newcoverage.end(); iter++) {
			WARN("Found %zd new offsets befor DEBUGGER_TARGET_START %s\n", iter->offsets.size(), iter->module_name.c_str());
		}
		instrumentation->IgnoreCoverage(newcoverage);

		status = instrumentation->Continue(timeout);
	}

	switch (status) {
	case DEBUGGER_CRASHED:
		printf("Process crashed\n");
		instrumentation->Kill();
		return "CRASH:xxx";
		break;
	case DEBUGGER_HANGED:
		printf("Process hanged\n");
		instrumentation->Kill();
		return ("ERR: Process hanged\n");
		break;
	case DEBUGGER_PROCESS_EXIT:
		if (instrumentation->IsTargetFunctionDefined()) {
			return ("ERR: Process exit during target function\n");
		}
		else {
			return ("Process finished normally\n");
		}
		break;
	case DEBUGGER_TARGET_END:
		if (instrumentation->IsTargetFunctionDefined()) {
			return ("OK: Target function returned normally\n");
			cur_iteration++;
		}
		else {
			return ("ERR: Unexpected status received from the debugger\n");
		}
		break;
	default:
		return ("ERR: Unexpected status received from the debugger\n");
		break;
	}
}

int main(int argc, char** argv)
{
	instrumentation = new LiteCov();
	instrumentation->Init(argc, argv);

	int target_opt_ind = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			target_opt_ind = i + 1;
			break;
		}
	}

	int target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;
	char** target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;

	unsigned int pid = GetIntOption("-pid", argc, argv, 0);
	persist = GetBinaryOption("-persist", argc, argv, false);
	num_iterations = GetIntOption("-iterations", argc, argv, 1);
	char* outfile = GetOption("-coverage_file", argc, argv);

	//最新coverage 数量，小于该数量则当作没有新的路径
	unsigned int min_cov = GetIntOption("-min_cov", argc, argv, 32);

	if (!target_argc && !pid) {
		printf("Usage:\n");
		printf("%s <options> -- <target command line>\n", argv[0]);
		printf("Or:\n");
		printf("%s <options> -pid <pid to attach to>\n", argv[0]);
		return 0;
	}


	Coverage coverage, newcoverage;

	//如果有  outfile，则先读取现有的覆盖度情况，并且应用到本次执行
	//调用者 负责管理 outfile
	if (outfile) {
		ReadCoverageBinary(coverage, outfile);
		instrumentation->IgnoreCoverage(coverage);
		for (auto iter = coverage.begin(); iter != coverage.end(); iter++) {
			printf("ReadCoverageBinary size %zd in %s\n", iter->offsets.size(), iter->module_name.c_str());
		}
	}

	for (int i = 0; i < num_iterations; i++) {
		printf("start fuzz iter %d\n", i);
		std::string ret_str = RunTarget(target_argc, target_argv, pid, 0 == i ? 32 * 1000 : 20 * 1000);

		Coverage newcoverage;

		instrumentation->GetCoverage(newcoverage, true);

		BOOL find_new_coverage = false;
		size_t offset_count = 0;
		for (auto iter = newcoverage.begin(); iter != newcoverage.end(); iter++) {
			if (iter->offsets.size() >= min_cov)
				find_new_coverage = true;

			offset_count = iter->offsets.size();
			printf("%s_OFFSET_CNT:%zd\n", iter->module_name.c_str(), offset_count);
			//printf("Found %zd new offsets in %s\n", iter->offsets.size(), iter->module_name.c_str());
		}

		//WriteCoverage(newcoverage, "111.txt");
		//如果 coverage 太少则当作当前文件没有 新路径发现
		if (find_new_coverage) {
			instrumentation->IgnoreCoverage(newcoverage);

			MergeCoverage(coverage, newcoverage);


			//先写到临时文件，成功后替换，防止因为进程被结束导致覆盖度文件被破坏
			if (outfile) {
				char tmp_name[256] = {};
				sprintf_s(tmp_name, "%s_%x", outfile, i);

				//printf("WriteCoverageBinary\n");
				WriteCoverageBinary(coverage, tmp_name);


				//printf("CopyFileA\n");
				CopyFileA(tmp_name, outfile, FALSE);
				//printf("DeleteFileA\n");
				DeleteFileA(tmp_name);
			}

		}

		printf("FUZZITER:idx:%d, find_new_coverage:%d, msg:%s\n", i, find_new_coverage, ret_str.c_str());

		_flushall();

		if (-1 == ret_str.find("OK:")) {
			break;
		}
	}

	instrumentation->Kill();

	return 0;
}

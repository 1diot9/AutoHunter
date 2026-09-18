<script setup>
import { ref, onActivated, onDeactivated, onMounted, onUnmounted, computed, watch, nextTick } from "vue";
import { useRouter } from "vue-router";
import { api, authReadyRef, authRequiredRef, authRoleRef, loadAuthRole, verifyToken } from "../api.js";
import TaskEditModal from "../components/TaskEditModal.vue";
import DailyCalendar from "../components/DailyCalendar.vue";
import { taskListState } from "../taskListState.js";
import { showToast } from "../toast.js";

defineOptions({ name: "TasksView" });

const tasks = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const editOpen = ref(false);
const editingTask = ref(null);
const writable = computed(() => authRoleRef.value === "full");
const router = useRouter();

// ===== 任务置顶：选中态 / 操作中态 / 批量栏 =====
const selected = ref(new Set());       // 勾选的任务 id
const toggling = ref(new Set());       // 正在置顶/取消置顶中的任务 id（按钮禁用）
const pageIds = computed(() => pagedTasks.value.map((t) => t.id));
const allChecked = computed(() =>
  pageIds.value.length > 0 && pageIds.value.every((id) => selected.value.has(id))
);
const someChecked = computed(() => pageIds.value.some((id) => selected.value.has(id)));

function toast(msg, ms = 2400) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 260);
  }, ms);
}
function toggleRowChecked(id, checked) {
  const s = new Set(selected.value);
  if (checked) s.add(id); else s.delete(id);
  selected.value = s;   // 整体重新赋值触发响应式
}
function toggleAllChecked(checked) {
  selected.value = checked ? new Set(pageIds.value) : new Set();
}
// 单条置顶：按 id 在当前列表就地更新，无刷新。
// 注意：不能直接改传入的 t —— 任务列表有 5s 轮询，await 期间 t 可能已换成旧引用，
// 改它不会反映到渲染中的新对象；用 find 拿到当前列表里的同 id 对象再改。
async function toggleTop(t) {
  if (toggling.value.has(t.id)) return;
  const next = !t.is_top;
  toggling.value = new Set(toggling.value).add(t.id);
  try {
    await api.taskTop(t.id, next);
    const cur = tasks.value.find((x) => x.id === t.id);
    if (cur) cur.is_top = next;
    toast(next ? "已置顶" : "已取消置顶");
  } catch (e) {
    alert(`置顶失败：${e?.message || e}`);
  } finally {
    const s = new Set(toggling.value);
    s.delete(t.id);
    toggling.value = s;
  }
}
// 批量置顶：确认弹窗显示选中数量，成功后清空选择
async function batchTop(isTop) {
  const ids = [...selected.value];
  if (!ids.length) return;
  if (!confirm(`确认${isTop ? "置顶" : "取消置顶"}选中的 ${ids.length} 个任务？`)) return;
  try {
    const res = await api.taskBatchTop(ids, isTop);
    const ok = res?.success_count ?? 0;
    const fail = res?.failed_ids ?? [];
    const idSet = new Set(ids);
    tasks.value.forEach((t) => { if (idSet.has(t.id)) t.is_top = isTop; });
    toast(`成功${isTop ? "置顶" : "取消置顶"} ${ok} 个任务${fail.length ? `，${fail.length} 个失败` : ""}`);
    selected.value = new Set();
  } catch (e) {
    alert(`批量操作失败：${e?.message || e}`);
  }
}
let pollTimer = null;

// 搜索与排序
const searchQuery = ref("");
const sortBy = ref("created"); // created | pinyin
const _pinyinCollator = new Intl.Collator("zh-Hans-CN", { sensitivity: "accent" });

// 分页与筛选 —— 从位置记忆模块恢复上次位置
const page = ref(taskListState.hasSavedState ? taskListState.page : 0);                 // 当前页，0-based
const pageSize = ref(taskListState.hasSavedState ? taskListState.pageSize : 20);            // 每页数量
const PAGE_SIZE_OPTIONS = [10, 20, 50, 100];
const filterBy = ref("all");         // all | review_archived | discarded | pending_reg

// 日历筛选：点击日历统计卡片后激活，按 task_id 精确过滤任务列表
// { date, category, label, count, taskIds } | null
const calendarFilter = ref(null);

function applyCalendarFilter(payload) {
  // 同一卡片再次点击 -> 取消筛选
  if (calendarFilter.value &&
      calendarFilter.value.date === payload.date &&
      calendarFilter.value.category === payload.category) {
    calendarFilter.value = null;
  } else {
    calendarFilter.value = payload;
  }
  page.value = 0;
}

function clearCalendarFilter() {
  calendarFilter.value = null;
  page.value = 0;
}

const filteredTasks = computed(() => {
  let list = tasks.value;
  const q = searchQuery.value.trim().toLowerCase();
  if (q) {
    list = list.filter((t) =>
      (t.name || "").toLowerCase().includes(q) ||
      (t.fofa_query || "").toLowerCase().includes(q)
    );
  }
  // 筛选：待复审/AI未采纳（红点+绿点）/ AI已作废（灰点）/ 待注册目标
  if (filterBy.value === "review_archived") {
    list = list.filter((t) => (t.pending_user_review > 0) || (t.pending_archived > 0));
  } else if (filterBy.value === "discarded") {
    list = list.filter((t) => (t.pending_discarded > 0));
  } else if (filterBy.value === "pending_reg") {
    list = list.filter((t) => (t.pending_input ?? 0) > 0);
  }
  // 日历筛选：精确按 task_id 过滤（与上面的 pending 计数筛选可叠加）
  if (calendarFilter.value) {
    const idSet = new Set(calendarFilter.value.taskIds);
    list = list.filter((t) => idSet.has(t.id));
  }
  const sorted = [...list];
  if (sortBy.value === "pinyin") {
    sorted.sort((a, b) => _pinyinCollator.compare(a.name || "", b.name || ""));
  } else {
    sorted.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
  }
  return sorted;
});

const totalFiltered = computed(() => filteredTasks.value.length);
const totalPages = computed(() => Math.max(1, Math.ceil(totalFiltered.value / pageSize.value)));
const pagedTasks = computed(() => {
  const start = page.value * pageSize.value;
  return filteredTasks.value.slice(start, start + pageSize.value);
});

function prevPage() { if (page.value > 0) page.value--; }
function nextPage() { if (page.value < totalPages.value - 1) page.value++; }

const STATUS_LABEL = {
  running: "运行中",
  idle: "空闲",
  paused: "已暂停",
  stopped: "已停止",
  created: "未启动",
};
function taskModeLabel(t) {
  return t?.src_type === "enterprise" ? "企业SRC" : "EduSRC";
}
function engineLabel(engine) {
  return {
    fofa: "FOFA",
    quake: "360 Quake",
    hunter: "Hunter",
    zoomeye: "ZoomEye",
    shodan: "Shodan",
    censys: "Censys",
  }[engine] || engine || "";
}
function targetSourceLabel(t) {
  const source = t?.target_source;
  const eng = engineLabel(t?.engine);
  if (source === "manual") return "手动清单";
  if (source === "site") return "单站协作";
  if (source === "both") return eng ? `${eng}+手动` : "测绘+手动";
  if (source === "fofa") return eng || "测绘搜集";
  return source || "-";
}
function taskScopeText(t) {
  if (t?.target_source === "site") {
    return t.fofa_query || t.manual_targets?.[0] || "单站协作";
  }
  return t?.fofa_query || "手动清单";
}

const hasRunning = computed(() => tasks.value.some((t) => t.status === "running"));

function syncPoller() {
  clearInterval(pollTimer);
  pollTimer = null;
  // 有运行中任务时加快刷新；否则慢轮询，仍能感知远端状态变化。
  const ms = hasRunning.value ? 5000 : 15000;
  pollTimer = setInterval(() => load({ background: true }), ms);
}

async function load(opts = {}) {
  const background = !!opts.background;
  if (!tasks.value.length) initialLoading.value = true;
  else if (!background) refreshing.value = true;
  try { tasks.value = await api.listTasks(); }
  finally {
    initialLoading.value = false;
    refreshing.value = false;
    syncPoller();
  }
}
async function openEdit(task) {
  try {
    editingTask.value = await api.getTask(task.id);
    editOpen.value = true;
  } catch (e) {
    // 用可见的 alert 反馈；delError 只在删除确认弹窗内渲染，编辑失败时不可见。
    alert(`加载任务失败：${e?.message || e}`);
  }
}
// ===== 删除任务：二次确认 + 输入 full 令牌校验 =====
const delTarget = ref(null);       // 待删除的任务对象（弹窗打开时非空）
const delToken = ref("");          // 用户输入的 full 令牌
const delError = ref("");
const deleting = ref(false);

function askDelete(task) {
  delTarget.value = task;
  delToken.value = "";
  delError.value = "";
}
function cancelDelete() {
  if (deleting.value) return;
  delTarget.value = null;
  delToken.value = "";
  delError.value = "";
}
async function confirmDelete() {
  if (!delTarget.value || deleting.value) return;
  const task = delTarget.value;
  // 仅当服务端开启鉴权时，才要求再次输入 full 令牌做二次校验。
  if (authRequiredRef.value) {
    if (!delToken.value.trim()) {
      delError.value = "请输入 full 权限令牌以确认删除";
      return;
    }
    deleting.value = true;
    delError.value = "";
    const role = await verifyToken(delToken.value);
    if (role !== "full") {
      deleting.value = false;
      delError.value = role === "none" ? "令牌无效" : "该令牌不是 full 权限，无法删除";
      return;
    }
  } else {
    deleting.value = true;
  }
  try {
    await api.deleteTask(task.id, delToken.value);
    tasks.value = tasks.value.filter((t) => t.id !== task.id);
    delTarget.value = null;
    delToken.value = "";
  } catch (e) {
    delError.value = `删除失败：${e.message || e}`;
  } finally {
    deleting.value = false;
  }
}
function closeEdit() {
  editOpen.value = false;
  editingTask.value = null;
}
function onSaved() {
  closeEdit();
  load();
}

// ===== 批量暂停/启动 =====
const batchBusy = ref(false);
const batchMsg = ref("");
// ===== 单任务启动/暂停（列表内快捷操作） =====
const busyTaskIds = ref([]);    // 正在操作的任务 id 集合（按任务加锁，不互斥其它任务）
const actionMsg = ref("");      // 单任务操作结果反馈

async function ctl(task, action) {
  if (busyTaskIds.value.includes(task.id)) return; // 仅防同一任务重复点击
  // 已完成任务（所有目标均已处理完毕）点击启动：右下角提示，不真正发起启动请求
  if (action === "start" && (task.progress_pct ?? 0) >= 100) {
    showToast(`「${task.name}」任务已完成`);
    return;
  }
  busyTaskIds.value = [...busyTaskIds.value, task.id];
  actionMsg.value = "";
  try {
    await api[action](task.id);
    actionMsg.value = action === "start"
      ? `已启动「${task.name}」`
      : action === "pause" ? `已暂停「${task.name}」` : "操作完成";
    await load();
  } catch (e) {
    actionMsg.value = `操作失败：${e.message || e}`;
  } finally {
    busyTaskIds.value = busyTaskIds.value.filter(id => id !== task.id);
    setTimeout(() => (actionMsg.value = ""), 3000);
  }
}

async function batchPause() {
  batchBusy.value = true;
  batchMsg.value = "";
  try {
    const res = await api.batchPause();
    batchMsg.value = `已暂停 ${res.paused} 个任务`;
    await load();
  } catch (e) {
    batchMsg.value = `暂停失败：${e.message || e}`;
  } finally {
    batchBusy.value = false;
    setTimeout(() => (batchMsg.value = ""), 3000);
  }
}

async function batchStart() {
  batchBusy.value = true;
  batchMsg.value = "";
  try {
    const res = await api.batchStart();
    batchMsg.value = `已启动 ${res.started} 个任务`;
    await load();
  } catch (e) {
    batchMsg.value = `启动失败：${e.message || e}`;
  } finally {
    batchBusy.value = false;
    setTimeout(() => (batchMsg.value = ""), 3000);
  }
}
// 持续追踪滚动位置（passive 监听，性能开销极小）
// 这样即便 DOM 拆除时 window.scrollY 已失效，保存值仍是最后一次有效位置
function _saveScrollPos() {
  taskListState.scrollTop = window.scrollY;
}
onMounted(async () => {
  window.addEventListener("scroll", _saveScrollPos, { passive: true });
  if (!authReadyRef.value) await loadAuthRole();
  await load();
  // 恢复上次的滚动位置——需等待浏览器完成导航引起的滚动重置 + 组件渲染后再恢复
  if (taskListState.hasSavedState && taskListState.scrollTop > 0) {
    const target = taskListState.scrollTop;
    await nextTick();
    // 双 rAF 确保 DOM 布局完成，再用 setTimeout 兜底处理异步组件（如 DailyCalendar）渲染后的高度变化
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        window.scrollTo(0, target);
      });
    });
    setTimeout(() => window.scrollTo(0, target), 150);
  }
});
onUnmounted(() => {
  window.removeEventListener("scroll", _saveScrollPos);
  // 保存当前分页位置和滚动位置
  taskListState.page = page.value;
  taskListState.pageSize = pageSize.value;
  taskListState.hasSavedState = true;
});
onActivated(() => {
  if (tasks.value.length) load({ background: true });
  syncPoller();
});
onDeactivated(() => {
  clearInterval(pollTimer);
  pollTimer = null;
});
onUnmounted(() => {
  clearInterval(pollTimer);
  pollTimer = null;
});
watch(authReadyRef, (ready) => {
  if (ready) load();
});
// 搜索/排序/筛选/每页数量变化时回到第一页
watch([searchQuery, sortBy, filterBy, pageSize], () => { page.value = 0; });
// 数据增删后当前页可能越界，收敛到末页
watch(totalPages, (tp) => { if (page.value > tp - 1) page.value = tp - 1; });
watch(hasRunning, () => syncPoller());
</script>

<template>
  <section class="view tasks-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>
    <header class="page-head">
      <div class="toolbar-row">
        <input v-model="searchQuery" class="task-search" placeholder="搜索任务名/FOFA语法…" />
        <select v-model="filterBy" class="task-sort">
          <option value="all">全部任务</option>
          <option value="review_archived">待复审 / AI未采纳</option>
          <option value="discarded">AI已作废</option>
          <option value="pending_reg">待注册目标</option>
        </select>
        <select v-model="sortBy" class="task-sort">
          <option value="created">按创建时间</option>
          <option value="pinyin">按拼音排序</option>
        </select>
      </div>
      <div>
        <h2>任务列表</h2>
        <p class="page-sub">点击进入指挥台，查看实时看板与复审队列</p>
      </div>
      <div class="head-actions">
        <router-link v-if="authRoleRef !== 'observer'" class="head-action vuln-entry" to="/vulns">
          全局漏洞库
        </router-link>
        <router-link class="head-action" to="/hard-targets">全局硬骨头库</router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="head-action intel-entry" to="/intel">
          <span class="ie-dot" aria-hidden="true"></span>全局情报库
        </router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="head-action" to="/knowledge">
          人工知识库
        </router-link>
        <router-link v-if="authRoleRef !== 'observer'" class="head-action" to="/runtime-logs">
          运行异常
        </router-link>
      </div>
      <div class="batch-bar">
        <span v-if="batchMsg || actionMsg" class="batch-msg">{{ batchMsg || actionMsg }}</span>
        <div class="toolbar-spacer"></div>
        <button v-if="writable" class="batch-btn batch-pause" :disabled="batchBusy" @click="batchPause">
          {{ batchBusy ? "处理中…" : "全部暂停" }}
        </button>
        <button v-if="writable" class="batch-btn batch-start" :disabled="batchBusy" @click="batchStart">
          {{ batchBusy ? "处理中…" : "全部开始" }}
        </button>
      </div>
    </header>
    <DailyCalendar :active-filter="calendarFilter" @select="applyCalendarFilter" />
    <div v-if="calendarFilter" class="calendar-filter-banner">
      <span class="cfb-label">
        日历筛选：{{ calendarFilter.date }} · {{ calendarFilter.label }}
        <em class="cfb-count">{{ calendarFilter.count }} 项</em>
      </span>
      <span class="cfb-sep">|</span>
      <span class="cfb-match">匹配 {{ totalFiltered }} 个任务</span>
      <button class="cfb-clear" type="button" @click="clearCalendarFilter">清除筛选 ×</button>
    </div>
    <div v-if="initialLoading" class="task-list">
      <div v-for="n in 4" :key="n" class="task-card skeleton-task" aria-hidden="true">
        <div class="task-card-main">
          <div class="tc-title"><span class="sk-bar sk-title"></span></div>
          <div class="task-card-meta">
            <span class="sk-bar sk-badge"></span>
            <span class="sk-bar sk-meta"></span>
          </div>
          <div class="task-query sk-query-wrap">
            <span class="sk-bar sk-query"></span>
            <span class="sk-bar sk-query short"></span>
          </div>
        </div>
        <div class="task-card-side">
          <span class="sk-bar sk-time"></span>
          <div class="task-actions">
            <span class="sk-bar sk-action"></span>
            <span class="sk-bar sk-action"></span>
            <span class="sk-bar sk-action"></span>
          </div>
        </div>
      </div>
    </div>
    <div v-else-if="!tasks.length" class="empty">
      还没有任务
      <span class="hint">点顶栏「新建」创建第一个挖掘任务</span>
    </div>
    <div v-else-if="!totalFiltered" class="empty">
      没有匹配的任务
      <span class="hint">调整搜索词或筛选条件</span>
    </div>
    <div v-else class="task-list">
      <div v-if="writable" class="pin-batch-bar">
        <label class="pin-sel-all">
          <input type="checkbox" :checked="allChecked"
                 :indeterminate.prop="someChecked && !allChecked"
                 @change="toggleAllChecked($event.target.checked)" />
          全选本页
        </label>
        <span class="pin-sel-count">已选 {{ selected.size }} 个</span>
        <button class="btn-pin" type="button" :disabled="!someChecked" @click="batchTop(true)">批量置顶</button>
        <button class="btn-ghost" type="button" :disabled="!someChecked" @click="batchTop(false)">批量取消置顶</button>
      </div>
      <div v-for="t in pagedTasks" :key="t.id" class="task-card" :class="{
          live: t.status === 'running' && !t.retest_active,
          retest: t.status === 'running' && t.retest_active,
          pinned: t.is_top,
        }"
        @click="router.push(`/task/${t.id}`)">
        <div class="task-card-main">
          <div class="tc-title">
            <input v-if="writable" class="row-check" type="checkbox" :checked="selected.has(t.id)"
                   @click.stop @change="toggleRowChecked(t.id, $event.target.checked)" />
            <span v-if="t.is_top" class="pin-mark" aria-hidden="true">★</span>
            <span v-if="t.status === 'running'" class="pulse" :class="{ warn: t.retest_active }"></span>
            <b>{{ t.name }}</b>
          </div>
          <span v-if="t.pending_user_review > 0" class="review-dot"
                :title="`${t.pending_user_review} 个漏洞待复审`">{{ t.pending_user_review }}</span>
          <span v-if="t.pending_archived > 0" class="archived-dot"
                :title="`${t.pending_archived} 个漏洞 AI 未采纳`">{{ t.pending_archived }}</span>
          <span v-if="t.pending_discarded > 0" class="discarded-dot"
                :title="`${t.pending_discarded} 个漏洞 AI 已作废`">{{ t.pending_discarded }}</span>
          <div class="task-card-meta">
            <span class="badge" :class="t.status">{{ STATUS_LABEL[t.status] || t.status }}</span>
            <span class="meta">{{ taskModeLabel(t) }} · {{ targetSourceLabel(t) }} · 并发 {{ t.concurrency }} · 深挖 ×{{ t.deepen_cap ?? 2 }}</span>
            <span v-if="t.llm_cost > 0" class="task-cost-badge">¥{{ t.llm_cost.toFixed(2) }}</span>
          </div>
          <div class="meta task-query">{{ taskScopeText(t) }}</div>
          <div v-if="t.progress_pct > 0 || t.status === 'running' || t.status === 'paused' || t.status === 'stopped'" class="task-progress-row">
            <span class="task-progress-track"><i :style="{ width: (t.progress_pct || 0) + '%' }" :class="{ done: t.progress_pct >= 100 }"></i></span>
            <span class="task-progress-label">{{ t.progress_pct || 0 }}%</span>
          </div>
        </div>
        <div class="task-card-side">
          <time class="meta task-time">{{ t.created_at.slice(0, 19).replace("T", " ") }}</time>
          <div v-if="writable" class="task-actions">
            <button class="mini-action primary" type="button"
              :disabled="busyTaskIds.includes(t.id) || t.status === 'running'"
              @click.stop="ctl(t, 'start')">启动</button>
            <button class="mini-action" type="button"
              :disabled="busyTaskIds.includes(t.id) || t.status !== 'running'"
              @click.stop="ctl(t, 'pause')">暂停</button>
            <button class="mini-action pin" type="button" :class="{ on: t.is_top }"
                    :disabled="toggling.has(t.id)" @click.stop="toggleTop(t)">
              {{ toggling.has(t.id) ? "…" : (t.is_top ? "取消置顶" : "置顶") }}
            </button>
            <button class="mini-action" type="button" @click.stop="openEdit(t)">编辑参数</button>
            <button class="mini-action danger" type="button" @click.stop="askDelete(t)">删除</button>
          </div>
          <span class="task-chevron" aria-hidden="true">›</span>
        </div>
      </div>
    </div>
    <div v-if="!initialLoading && totalFiltered > pageSize" class="hard-pager task-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0">上一页</button>
      <span>第 {{ page + 1 }} / {{ totalPages }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + pagedTasks.length }} / {{ totalFiltered }}</span>
      <button type="button" @click="nextPage" :disabled="page >= totalPages - 1">下一页</button>
      <label class="pager-size">每页
        <select v-model="pageSize" class="task-sort">
          <option v-for="n in PAGE_SIZE_OPTIONS" :key="n" :value="n">{{ n }}</option>
        </select>
      </label>
    </div>
    <TaskEditModal :open="editOpen" :task="editingTask" @close="closeEdit" @saved="onSaved" />

    <div v-if="delTarget" class="modal-mask" @click.self="cancelDelete">
      <div class="modal-card del-modal" role="dialog" aria-modal="true">
        <h3 class="del-title">删除任务</h3>
        <p class="del-desc">
          即将删除任务 <b>「{{ delTarget.name }}」</b>。
        </p>
        <p class="del-warn">
          此操作会一并删除该任务的<b>全部目标、漏洞、审核与通杀记录</b>，且<b>不可恢复</b>。
          （全局情报库不受影响）
        </p>
        <label v-if="authRequiredRef" class="del-field">
          <span>请输入 <b>full 权限令牌</b>以确认</span>
          <input v-model="delToken" type="password" autocomplete="off"
            placeholder="full 访问令牌" @keyup.enter="confirmDelete" />
        </label>
        <p v-if="delError" class="del-error">{{ delError }}</p>
        <div class="del-actions">
          <button class="mini-action" type="button" :disabled="deleting" @click="cancelDelete">取消</button>
          <button class="mini-action danger" type="button" :disabled="deleting" @click="confirmDelete">
            {{ deleting ? "删除中…" : "确认删除" }}
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
/* 日历筛选激活横幅：点击日历统计卡片后显示 */
.calendar-filter-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  background: var(--accent-bg, rgba(79, 140, 255, 0.08));
  border: 1px solid var(--accent, #4f8cff);
  border-radius: var(--radius, 8px);
  padding: 8px 14px;
  margin-bottom: 12px;
  font-size: 13px;
  color: var(--ink);
}

.cfb-label { font-weight: 600; }
.cfb-count {
  font-style: normal;
  color: var(--accent, #4f8cff);
  margin-left: 4px;
  font-weight: 700;
}
.cfb-sep { color: var(--faint); }
.cfb-match { color: var(--muted); }

.cfb-clear {
  margin-left: auto;
  background: transparent;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm, 4px);
  color: var(--ink-2);
  font-size: 12px;
  padding: 4px 10px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}
.cfb-clear:hover {
  background: var(--surface-2);
  border-color: var(--danger);
  color: var(--danger);
}
</style>

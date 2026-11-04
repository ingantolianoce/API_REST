<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { messageFor } from '../api/http'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const router = useRouter()
const code = ref('')
const error = ref('')

async function submit() {
  error.value = ''
  try {
    await auth.verifyMfa(code.value.trim())
    await router.push('/')
  } catch (e) {
    code.value = ''
    error.value = messageFor(e)
  }
}
</script>

<template>
  <h1>Verificación en dos pasos</h1>
  <form @submit.prevent="submit">
    <label for="code">Código de la app autenticadora (o código de recuperación)</label>
    <input id="code" v-model="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="24" />
    <button type="submit">Verificar</button>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
  </form>
  <p><RouterLink to="/login">Volver</RouterLink></p>
</template>
